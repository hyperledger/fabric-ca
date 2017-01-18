FROM golang
ENV GOPATH=/opt/gopath
ENV PATH=$GOPATH/bin:$PATH

RUN go get github.com/hyperledger/fabric-ca

# Copy the configuration for the cop and certificate setups
WORKDIR /config
COPY config.json /config/config.json
COPY csr.json /config/csr.json

# Copy the same certificates that are currently hardcoded into the peers
WORKDIR /root/.fabric-ca
COPY ec-key.pem /root/.fabric-ca/ec-key.pem
COPY ec.pem /root/.fabric-ca/ec.pem

EXPOSE 8888
