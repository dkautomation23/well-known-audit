# ClusterFuzzLite runs the fuzz target on every pull request, against a corpus
# it keeps between runs. The image is OSS-Fuzz's JavaScript base builder, which
# brings Jazzer.js and libFuzzer with it.
FROM gcr.io/oss-fuzz-base/base-builder-javascript
COPY . $SRC/well-known-audit
COPY .clusterfuzzlite/build.sh $SRC/
WORKDIR $SRC/well-known-audit
