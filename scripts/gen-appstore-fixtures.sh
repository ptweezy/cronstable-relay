#!/bin/sh
# Regenerates the test-only certificate chain under tests/fixtures/appstore/
# that tests/appstore.spec.ts signs StoreKit-shaped transactions with.
#
# The shape mirrors Apple's real chain: a P-384 root self-signed with
# ecdsa-with-SHA384, a P-256 intermediate signed by the root with
# ecdsa-with-SHA384, and P-256 leaves signed by the intermediate with
# ecdsa-with-SHA256.  One leaf carries Apple's in-app purchase marker
# extension (1.2.840.113635.100.6.11.1), one deliberately lacks it, and
# two carry the marker but have run out:
#
#   leaf-lapsed   2023-09-12 to 2025-10-11, inside the root's and the
#                 intermediate's windows: a receipt-signing leaf Apple
#                 has rotated out, whose transactions still verify at
#                 their own signedDate.
#   leaf-expired  2020-01-01 to 2021-01-01, before the root and the
#                 intermediate begin, so no signedDate puts the whole
#                 chain inside its windows.
#
# Every validity window is a fixed date, so the suite can sign at any
# instant inside one: the root and the intermediate run from 2022-01-01
# to 2040-01-01, and the current leaves from 2022-01-01 to 2039-01-01.
# A second, unrelated root exists for the wrong-root case.  None of this
# key material is registered with Apple.  Only what the suite loads
# survives: the DER certificates and the leaf private keys it signs with
# at runtime.  The CA keys and the PEM copies are removed once the chain
# is built, so nothing can mint new leaves for the test root after the
# fact.
#
#   sh scripts/gen-appstore-fixtures.sh
#
# Needs OpenSSL 3.4 or later (-not_before/-not_after on req and x509).
set -eu

OPENSSL="${OPENSSL:-openssl}"
OUT="$(cd "$(dirname "$0")/.." && pwd)/tests/fixtures/appstore"
mkdir -p "$OUT"
cd "$OUT"

CA_NOT_BEFORE=20220101000000Z
CA_NOT_AFTER=20400101000000Z
LEAF_NOT_BEFORE=20220101000000Z
LEAF_NOT_AFTER=20390101000000Z

# Root: P-384, self-signed, SHA-384.
"$OPENSSL" ecparam -name secp384r1 -genkey -noout -out root.key.pem
"$OPENSSL" req -new -x509 -key root.key.pem -sha384 \
  -not_before $CA_NOT_BEFORE -not_after $CA_NOT_AFTER \
  -subj "/CN=Test Root CA - G3/O=cronstable-relay tests" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out root.pem
"$OPENSSL" x509 -in root.pem -outform DER -out root.der

# An unrelated root for the wrong-root case.
"$OPENSSL" ecparam -name secp384r1 -genkey -noout -out other-root.key.pem
"$OPENSSL" req -new -x509 -key other-root.key.pem -sha384 \
  -not_before $CA_NOT_BEFORE -not_after $CA_NOT_AFTER \
  -subj "/CN=Some Other Root/O=cronstable-relay tests" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -out other-root.pem
"$OPENSSL" x509 -in other-root.pem -outform DER -out other-root.der

# Intermediate: P-256, signed by the root with SHA-384.
"$OPENSSL" ecparam -name prime256v1 -genkey -noout -out intermediate.key.pem
"$OPENSSL" req -new -key intermediate.key.pem \
  -subj "/CN=Test Worldwide Developer Relations CA/O=cronstable-relay tests" \
  -out intermediate.csr
cat > intermediate.ext <<EXT
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
EXT
"$OPENSSL" x509 -req -in intermediate.csr -CA root.pem -CAkey root.key.pem \
  -CAcreateserial -sha384 -not_before $CA_NOT_BEFORE \
  -not_after $CA_NOT_AFTER -extfile intermediate.ext \
  -out intermediate.pem
"$OPENSSL" x509 -in intermediate.pem -outform DER -out intermediate.der

# Leaves: P-256, signed by the intermediate with SHA-256.  Keys are
# written as PKCS#8 so the tests import them the way the relay imports
# its APNs .p8.
leaf() {
  name="$1"; ext="$2"; shift 2
  "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$name.key.pem"
  "$OPENSSL" req -new -key "$name.key.pem" \
    -subj "/CN=Test Mac App Store and iTunes Store Receipt Signing/O=cronstable-relay tests" \
    -out "$name.csr"
  printf '%s\n' "$ext" > "$name.ext"
  "$OPENSSL" x509 -req -in "$name.csr" -CA intermediate.pem \
    -CAkey intermediate.key.pem -CAcreateserial -sha256 \
    -extfile "$name.ext" "$@" -out "$name.pem"
  "$OPENSSL" x509 -in "$name.pem" -outform DER -out "$name.der"
  rm -f "$name.csr" "$name.ext"
}

MARKER='1.2.840.113635.100.6.11.1=ASN1:NULL'
leaf leaf "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
$MARKER" -not_before $LEAF_NOT_BEFORE -not_after $LEAF_NOT_AFTER
leaf leaf-nomarker "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature" \
  -not_before $LEAF_NOT_BEFORE -not_after $LEAF_NOT_AFTER
leaf leaf-lapsed "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
$MARKER" -not_before 20230912000000Z -not_after 20251011000000Z
leaf leaf-expired "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
$MARKER" -not_before 20200101000000Z -not_after 20210101000000Z

rm -f intermediate.csr intermediate.ext ./*.srl
rm -f root.pem intermediate.pem other-root.pem \
  leaf.pem leaf-nomarker.pem leaf-lapsed.pem leaf-expired.pem \
  root.key.pem intermediate.key.pem other-root.key.pem
chmod 644 ./*.pem ./*.der
echo "fixtures written to $OUT"
