FROM nvidia/cuda:12.2.0-devel-ubuntu22.04 AS build
COPY --from=golang:1.24-alpine /usr/local/go/ /usr/local/go/

ENV PATH="/usr/local/go/bin:${PATH}"


WORKDIR /app

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN GOOS=linux go build -o /app/server

FROM gcr.io/distroless/base-debian12
COPY --from=build /app/server /server
CMD ["/server"]