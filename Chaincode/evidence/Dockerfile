# Chaincode-as-a-service image for the evidence chaincode (JISA revision).
# Fabric 2.4.8 peers cannot build chaincode images on Docker Engine >= 29
# (the peer's built-in Docker client is refused), so the chaincode is built
# here with the same fabric-ccenv:2.4.8 toolchain and run as an external
# service via the peer's ccaas_builder.
FROM hyperledger/fabric-ccenv:2.4.8 AS build
USER root
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
COPY contracts ./contracts
RUN go build -mod=readonly -ldflags "-linkmode external -extldflags '-static'" -o /out/chaincode .

FROM hyperledger/fabric-baseos:2.4.8
COPY --from=build /out/chaincode /usr/local/bin/chaincode
ENV CHAINCODE_SERVER_ADDRESS=0.0.0.0:9999
EXPOSE 9999
CMD ["/usr/local/bin/chaincode"]
