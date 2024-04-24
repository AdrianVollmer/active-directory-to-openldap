#/bin/bash

# Use venv where python3-ldif is installed
. /var/venv/bin/activate

if [ ! -f /app/ldif_raw/base.ldif ] || [ ! -f /app/ldif_raw/schema.ldif  ]
then
    echo "Dumping LDIF ..."
    python3 ./dump-ldif.py \
        --user "${LDAP_USER}" \
        --domain "${LDAP_DOMAIN}" \
        --password "${LDAP_PASSWORD}" \
        --target-host "${LDAP_TARGET_HOST}" \
        --target-domain "${LDAP_TARGET_DOMAIN}" \
        --output-dir /app/ldif_raw
else
    echo "Reading files in /app/ldif_raw ..."
fi

echo "Creating schema ..."

python3 ./convert-ldif-to-schema.py \
    --src /app/ldif_raw/schema.ldif \
    --dst-attr /app/schema/microsoftattributetype.schema \
    --dst-class /app/schema/microsoftobjectclass.schema \

echo "Sorting ldif ..."

python3 ./sort-ldif.py \
    --src /app/ldif_raw/base.ldif \
    --dst /app/ldif/base.ldif
