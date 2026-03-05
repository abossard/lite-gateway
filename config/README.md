# Example: Mounted YARP Configuration for Header Injection
#
# This file shows how to configure header injection via the mounted
# /config/yarp.json file. Mount this into the container to override
# the baked-in defaults without rebuilding the image.
#
# ─────────────────────────────────────────────────────────
# Example 1: Single header injection
# ─────────────────────────────────────────────────────────
#
# config/yarp.json:
# {
#   "ReverseProxy": {
#     "Routes": {
#       "catch-all": {
#         "Transforms": [
#           { "RequestHeader": "TEST-ID", "Set": "1234" }
#         ]
#       }
#     },
#     "Clusters": {
#       "upstream": {
#         "Destinations": {
#           "default": { "Address": "http://backend:8080" }
#         }
#       }
#     }
#   }
# }
#
# ─────────────────────────────────────────────────────────
# Example 2: Multiple headers
# ─────────────────────────────────────────────────────────
#
# "Transforms": [
#   { "RequestHeader": "TEST-ID", "Set": "1234" },
#   { "RequestHeader": "X-Tenant-ID", "Set": "tenant-abc" },
#   { "RequestHeader": "X-Source", "Append": "yarp-gateway" }
# ]
#
# ─────────────────────────────────────────────────────────
# Example 3: Via environment variables (no config file needed)
# ─────────────────────────────────────────────────────────
#
# docker run \
#   -e ReverseProxy__Routes__catch-all__Transforms__0__RequestHeader=TEST-ID \
#   -e ReverseProxy__Routes__catch-all__Transforms__0__Set=1234 \
#   yarp-proxy
#
# ─────────────────────────────────────────────────────────
# Example 4: Via PROXY_HEADER_* env vars (entrypoint script)
# ─────────────────────────────────────────────────────────
#
# docker run \
#   -e PROXY_HEADER_TEST_ID=1234 \
#   -e PROXY_HEADER_X_CORRELATION_ID=abc-123 \
#   yarp-proxy
#
# This translates to headers:
#   TEST-ID: 1234
#   X-CORRELATION-ID: abc-123
#
# ─────────────────────────────────────────────────────────
# Dynamic ENV var name scenario
# ─────────────────────────────────────────────────────────
#
# External system provides: TEST_123_ID=1234
# In docker-compose.yml, map it to the standard name:
#
#   environment:
#     PROXY_HEADER_TEST_ID: "${TEST_123_ID}"
#
# Later when the external var changes to TEST_456_ID:
#
#   environment:
#     PROXY_HEADER_TEST_ID: "${TEST_456_ID}"
#
# The Docker image and YARP config stay identical.
