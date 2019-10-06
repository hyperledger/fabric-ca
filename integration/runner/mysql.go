/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package runner

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	docker "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
	_ "github.com/go-sql-driver/mysql" //Driver passed to the sqlx package
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
	"github.com/tedsuo/ifrit"
)

// MySQLDefaultImage is used if none is specified
const MySQLDefaultImage = "mysql:5.7"

// MySQL defines a containerized MySQL Server
type MySQL struct {
	Client          *docker.Client
	Image           string
	HostIP          string
	HostPort        int
	Name            string
	ContainerPort   int
	StartTimeout    time.Duration
	ShutdownTimeout time.Duration

	ErrorStream  io.Writer
	OutputStream io.Writer

	containerID      string
	hostAddress      string
	containerAddress string

	mutex   sync.Mutex
	stopped bool
}

// Run is called by the ifrit runner to start a process
func (c *MySQL) Run(sigCh <-chan os.Signal, ready chan<- struct{}) error {
	if c.Image == "" {
		c.Image = MySQLDefaultImage
	}

	if c.Name == "" {
		c.Name = DefaultNamer()
	}

	if c.HostIP == "" {
		c.HostIP = "127.0.0.1"
	}

	if c.StartTimeout == 0 {
		c.StartTimeout = DefaultStartTimeout
	}

	if c.ShutdownTimeout == 0 {
		c.ShutdownTimeout = time.Duration(DefaultShutdownTimeout)
	}

	if c.ContainerPort == 0 {
		c.ContainerPort = 3306
	}

	port, err := nat.NewPort("tcp", strconv.Itoa(c.ContainerPort))
	if err != nil {
		return err
	}

	if c.Client == nil {
		client, err := docker.NewClientWithOpts(docker.FromEnv)
		if err != nil {
			return err
		}
		client.NegotiateAPIVersion(context.Background())
		c.Client = client
	}

	hostConfig := &container.HostConfig{
		AutoRemove: true,
		PortBindings: nat.PortMap{
			"3306/tcp": []nat.PortBinding{
				{
					HostIP:   c.HostIP,
					HostPort: strconv.Itoa(c.HostPort),
				},
			},
		},
	}
	containerConfig := &container.Config{
		Image: c.Image,
		Env: []string{
			"MYSQL_ALLOW_EMPTY_PASSWORD=yes",
		},
	}

	containerResp, err := c.Client.ContainerCreate(context.Background(), containerConfig, hostConfig, nil, c.Name)
	if err != nil {
		return err
	}
	c.containerID = containerResp.ID

	err = c.Client.ContainerStart(context.Background(), c.containerID, types.ContainerStartOptions{})
	if err != nil {
		return err
	}
	defer c.Stop()

	response, err := c.Client.ContainerInspect(context.Background(), c.containerID)
	if err != nil {
		return err
	}

	if c.HostPort == 0 {
		port, err := strconv.Atoi(response.NetworkSettings.Ports[port][0].HostPort)
		if err != nil {
			return err
		}
		c.HostPort = port
	}

	c.hostAddress = net.JoinHostPort(
		response.NetworkSettings.Ports[port][0].HostIP,
		response.NetworkSettings.Ports[port][0].HostPort,
	)
	c.containerAddress = net.JoinHostPort(
		response.NetworkSettings.IPAddress,
		port.Port(),
	)

	streamCtx, streamCancel := context.WithCancel(context.Background())
	defer streamCancel()
	go c.streamLogs(streamCtx)

	containerExit := c.wait()
	ctx, cancel := context.WithTimeout(context.Background(), c.StartTimeout)
	defer cancel()

	select {
	case <-ctx.Done():
		return errors.Wrapf(ctx.Err(), "database in container %s did not start", c.containerID)
	case <-containerExit:
		return errors.New("container exited before ready")
	case <-c.ready(ctx):
		break
	}

	cancel()
	close(ready)

	for {
		select {
		case err := <-containerExit:
			return err
		case <-sigCh:
			err := c.Stop()
			if err != nil {
				return err
			}
			return nil
		}
	}
}

func (c *MySQL) endpointReady(ctx context.Context, db *sqlx.DB) bool {
	conn, err := db.Conn(ctx)
	if err != nil {
		return false
	}

	conn.QueryContext(ctx, "SET GLOBAL sql_mode = '';")
	db.Close()

	return true
}

func (c *MySQL) ready(ctx context.Context) <-chan struct{} {
	readyCh := make(chan struct{})

	str := fmt.Sprintf("root:@(%s:%d)/mysql", c.HostIP, c.HostPort)
	db, err := sqlx.Open("mysql", str)
	if err != nil {
		ctx.Done()
	}

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			if c.endpointReady(ctx, db) {
				close(readyCh)
				return
			}
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return
			}
		}
	}()

	return readyCh
}

func (c *MySQL) wait() <-chan error {
	exitCh := make(chan error, 1)
	go func() {
		exitCode, errCh := c.Client.ContainerWait(context.Background(), c.containerID, container.WaitConditionNotRunning)
		select {
		case exit := <-exitCode:
			if exit.StatusCode != 0 {
				err := fmt.Errorf("mysql: process exited with %d", exit.StatusCode)
				exitCh <- err
			} else {
				exitCh <- nil
			}
		case err := <-errCh:
			exitCh <- err
		}
	}()

	return exitCh
}

func (c *MySQL) streamLogs(ctx context.Context) {
	if c.ErrorStream == nil && c.OutputStream == nil {
		return
	}

	logOptions := types.ContainerLogsOptions{
		Follow:     true,
		ShowStderr: c.ErrorStream != nil,
		ShowStdout: c.OutputStream != nil,
	}

	out, err := c.Client.ContainerLogs(ctx, c.containerID, logOptions)
	if err != nil {
		fmt.Fprintf(c.ErrorStream, "log stream ended with error: %s", out)
	}
	stdcopy.StdCopy(c.OutputStream, c.ErrorStream, out)
}

// HostAddress returns the host address where this MySQL instance is available.
func (c *MySQL) HostAddress() string {
	return c.hostAddress
}

// ContainerAddress returns the container address where this MySQL instance
// is available.
func (c *MySQL) ContainerAddress() string {
	return c.containerAddress
}

// ContainerID returns the container ID of this MySQL instance
func (c *MySQL) ContainerID() string {
	return c.containerID
}

// Start starts the MySQL container using an ifrit runner
func (c *MySQL) Start() error {
	p := ifrit.Invoke(c)

	select {
	case <-p.Ready():
		return nil
	case err := <-p.Wait():
		return err
	}
}

// Stop stops and removes the MySQL container
func (c *MySQL) Stop() error {
	c.mutex.Lock()
	if c.stopped {
		c.mutex.Unlock()
		return errors.Errorf("container %s already stopped", c.containerID)
	}
	c.stopped = true
	c.mutex.Unlock()

	err := c.Client.ContainerStop(context.Background(), c.containerID, &c.ShutdownTimeout)
	if err != nil {
		return err
	}

	return nil
}

// GetConnectionString returns the sql connection string for connecting to the DB
func (c *MySQL) GetConnectionString() (string, error) {
	if c.HostIP != "" && c.HostPort != 0 {
		return fmt.Sprintf("root:@(%s:%d)/mysql", c.HostIP, c.HostPort), nil
	}
	return "", fmt.Errorf("mysql db not initialized")
}
