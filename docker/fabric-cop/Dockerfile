FROM golang
ENV GOPATH=/opt/gopath
ENV PATH=$GOPATH/bin:$PATH

RUN go get github.com/hyperledger/fabric-cop/cli
RUN mv $GOPATH/bin/cli $GOPATH/bin/cop

# Copy the configuration for the cop and certificate setups
WORKDIR /config
COPY cop.json /config/cop.json
COPY csr.json /config/csr.json

# Copy the same certificates that are currently hardcoded into the peers
WORKDIR /root/.cop
COPY ec-key.pem /root/.cop/ec-key.pem
COPY ec.pem /root/.cop/ec.pem

EXPOSE 8888
