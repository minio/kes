default: kes

.PHONY: kes
kes:
	@echo "Building kes binary to './kes'"
	@(cd cmd/kes; CGO_ENABLED=0 go build --ldflags "-s -w" -o ../../kes)

clean:
	@echo "Cleaning up all the generated files"
	@find . -name '*.test' | xargs rm -fv
	@find . -name '*~' | xargs rm -fv
	@rm -rvf kes

docker:
	@docker build -t minio/kes .

swagger-gen:
	@echo "Cleaning"
	@rm -rf models
	@rm -rf restapi/operations
	@echo "Generating swagger server code from yaml"
	@swagger generate server -A kes --main-package=management --server-package=restapi --exclude-main -P models.Principal -f ./swagger.yaml -r NOTICE