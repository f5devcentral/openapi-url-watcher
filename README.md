# openapi-url-watcher

This container will monitor OpenAPI external URLs listed in APPolicies and trigger "apreload" in NGINX App Protect if it detects a change in OpenAPI file. IT can be deployed as a standalone pod or deployment (# of replicas=1)