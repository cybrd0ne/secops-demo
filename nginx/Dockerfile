# Front door from Lab 3: nginx terminates TLS in front of OpenSearch Dashboards.
# Pinned by tag and digest, so the build never floats (Lab 3 check list).
# Fill the digest on your machine:
#   docker pull nginx:1.27-alpine
#   docker inspect --format '{{index .RepoDigests 0}}' nginx:1.27-alpine
FROM nginx:1.27-alpine@sha256:REPLACE_WITH_DIGEST

# Site config only. Certificates stay out of the image and are mounted at runtime
# from certs/ (git-ignored), exactly as in compose.yaml.
COPY frontdoor.conf /etc/nginx/conf.d/default.conf

EXPOSE 443
