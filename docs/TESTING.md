Project specific testing guides are here.

A general [testing guides](https://bitbucket.org/kalmiadevs/kalmia-common-lib/src/master/docs/TESTING.md) are a must read, and shall not be duplicated here. 

Tests need MySql database to be present. 
Docker image can be used to run local instance of MySQL. 

```bash
sudo docker run --name test-mysql -e MYSQL_ROOT_PASSWORD=test -p 3306:3306 -d mysql
```

For the CI support an docker image is prepared for testing. The dockerFile contains two stages, build and prod.

The build stage also runs the unit tests. The `docker-compose.test.yaml` file is used to setup the test environment (Also starts the mySql database).
To run the tests on docker, thw following commands shall be used (the access key is needed for nmp to access the linked packages):



```bash
# build Docker image
sudo AUTH_REPO_ACCESS_KEY="$(cat kalmia-auth-repo-access.key)" docker-compose -f docker-compose.test.yaml --env-file ./.env.test build --force

# run docker image
sudo AUTH_REPO_ACCESS_KEY="$(cat kalmia-auth-repo-access.key)" docker-compose -f docker-compose.test.yaml --env-file ./.env.test up --force-recreate --abort-on-container-exit --exit-code-from api
```




When te image is run with `up` it will exit with the proper exit code from the tests (1-error, 0-OK). This exit code shall be used by the CI build system.