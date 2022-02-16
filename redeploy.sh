#!/bin/bash

set -ex

yes | osm uninstall cluster-wide-resources || true

yes | osm uninstall mesh || true

kubectl delete ns osm-system || true

make docker-build-osm-controller

make build-osm

./bin/osm install --verbose --set=osm.image.registry=osmsteeling.azurecr.io --set=osm.image.tag=latest --set=osm.enablePermissiveTrafficPolicy=true --set=OpenServiceMesh.enablePermissiveTrafficPolicy=true --set=osm.image.pullPolicy=Always --set=osm.controllerLogLevel=trace

kubectl rollout restart deployment reviews-v1

kubectl rollout restart deployment productpage-v1

kubectl logs deployment/osm-controller -n osm-system > tmp.log