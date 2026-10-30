# The released service image (docs/phase0-deployment.md, "Release").
#
# Built only by scripts/release.py, from `git archive <tag>`, never from a working
# tree. The build context holds the crucible wheels built from that tag, the
# third-party requirements pinned by hash from uv.lock, the client's constraints
# (served to strangers), and RELEASE.json, which names the tag, its commit and
# every wheel's sha256. Nothing is installed editable, so the service's own
# refusal of an editable install never fires here.
ARG BASE=python:3.11-slim
FROM ${BASE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY requirements.txt /release/requirements.txt
COPY wheels/ /release/wheels/
RUN pip install --no-deps --require-hashes -r /release/requirements.txt \
 && pip install --no-deps /release/wheels/*.whl \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin crucible
COPY RELEASE.json README.md install.sh constraints.txt /release/
USER 10001
ENTRYPOINT ["crucible-service"]
