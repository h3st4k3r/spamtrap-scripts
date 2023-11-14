#!/bin/bash
# @author h3st4k3r
# @version 0.1

# Directorios, debéis cambiarlos con los vuestros claro
MAIL_DIR=""
ATTACHMENTS_DIR="/tmp/attachments"
PROCESSED_ATTACHMENTS_DIR="/var/log/clamav/processed_attachments"
LINKS_DOWNLOAD_DIR="/tmp/links"
PROCESSED_IDS_FILE="/var/log/clamav/processed_ids.log"
JSON_OUTPUT="/"

mkdir -p "$ATTACHMENTS_DIR"
mkdir -p "$LINKS_DOWNLOAD_DIR"
mkdir -p "$PROCESSED_ATTACHMENTS_DIR"
touch "$PROCESSED_IDS_FILE"
touch "$JSON_OUTPUT"

# Inicializar JSON si está vacío
if [ ! -s "$JSON_OUTPUT" ]; then
    echo "[]" > "$JSON_OUTPUT"
fi

# Función para extraer enlaces de un correo
extract_links() {
    local mail_file=$1
    grep -oP 'http[s]?://\S+' "$mail_file" | sort | uniq | tr '\n' ', ' | sed 's/, $//'
}

# Función para descargar y escanear el contenido de los enlaces
scan_links() {
    local links=$1
    IFS=', ' read -r -a url_array <<< "$links"
    for url in "${url_array[@]}"; do
        local file_name=$(basename "$url")
        wget -q -P "$LINKS_DOWNLOAD_DIR" "$url"
        local downloaded_file="$LINKS_DOWNLOAD_DIR/$file_name"
        if [ -f "$downloaded_file" ]; then
            clamscan "$downloaded_file"
            rm -f "$downloaded_file"
        fi
    done
}

# Función para procesar directorios de correo
process_mail_dir() {
    local mail_dir=$1
    for MAILFILE in "$mail_dir"/{new,cur}/*; do
        if [ ! -f "$MAILFILE" ]; then
            continue
        fi

        echo "Procesando correo: $MAILFILE"

        # Extraer el ID del mensaje del correo
        local message_id
        message_id=$(grep -i -m 1 -hI '^Message-ID:' "$MAILFILE" | sed -E 's/.*Message-ID: *<([^>]+)>.*/\1/i')
        
        if [ -z "$message_id" ]; then
            echo "No se pudo encontrar un ID de mensaje válido para el archivo: $MAILFILE"
            continue
        fi

        # Verificar si el ID del mensaje ya ha sido procesado
        if grep -Fxq "$message_id" "$PROCESSED_IDS_FILE"; then
            echo "Mensaje ya procesado: $message_id"
            continue
        fi

        # Extraer archivos adjuntos del correo electrónico
        ripmime -i "$MAILFILE" -d "$ATTACHMENTS_DIR"

        # Extraer asunto del correo
        local subject
        subject=$(grep -i -m 1 -hI '^Subject:' "$MAILFILE" | sed -E 's/Subject: //i')

        # Extraer cuerpo del correo
        local body
        body=$(grep -v '^\--' "$MAILFILE" | grep -A9999 '^$' | jq -aRs .)

        # Extraer enlaces y escanearlos
        local links
        links=$(extract_links "$MAILFILE" | jq -aRs .)
        scan_links "$links"

        # Escanear cada archivo adjunto y calcular el hash
        for FILE in "$ATTACHMENTS_DIR"/*; do
            if [ -f "$FILE" ]; then
                local hash
                hash=$(sha256sum "$FILE" | cut -d ' ' -f 1)
                local clamscan_output
                clamscan_output=$(clamscan "$FILE")
                local malware_detected="false"
                local malware_type=""
                
                if ! grep -q 'Infected files: 0' <<< "$clamscan_output"; then
                    malware_detected="true"
                    malware_type=$(echo "$clamscan_output" | grep FOUND | cut -d ' ' -f 2)
                fi

                # Crear un archivo temporal para los datos JSON
                json_input=$(mktemp)

                # Escribir los datos al archivo temporal
                cat <<EOF > "$json_input"
                {
                    "timestamp": "$(date +%F_%T)",
                    "message_id": "$message_id",
                    "file": "$FILE",
                    "hash": "$hash",
                    "malware_detected": "$malware_detected",
                    "malware_type": "$malware_type",
                    "subject": "$subject",
                    "body": $body,
                    "links": "$links"
                }
EOF

                # Usar el archivo temporal como entrada para jq
                json_entry=$(jq -n --slurpfile data "$json_input" '$data[0]')

                # Añadir el JSON al archivo
                local temp_json
                temp_json=$(mktemp)
                if jq ". += [$json_entry]" "$JSON_OUTPUT" > "$temp_json"; then
                    mv "$temp_json" "$JSON_OUTPUT"
                else
                    echo "Error al añadir datos al archivo JSON para el mensaje con ID: $message_id"
                    rm -f "$temp_json"
                fi

                # Eliminar el archivo temporal
                rm -f "$json_input"

                # Mover archivos adjuntos procesados para referencia futuras
                mv "$FILE" "$PROCESSED_ATTACHMENTS_DIR/"
            fi
        done

        # Agrega el ID del mensaje al archivo de control
        echo "$message_id" >> "$PROCESSED_IDS_FILE"
    done
}

process_mail_dir "$MAIL_DIR"

echo "Proceso terminado :)"
