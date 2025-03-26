#include "m3_debug.h"

static const char *TAG_DUMP = "BYTE_DUMP";

/**
 * @brief Stampa una serie di byte nel log
 * 
 * @param data Puntatore ai dati da stampare
 * @param length Lunghezza in byte dei dati
 */
 void log_bytes(const uint8_t *data, size_t length) {
    if (data == NULL) {
        ESP_LOGE(TAG_DUMP, "Puntatore nullo");
        return;
    }
    
    if (length == 0) {
        ESP_LOGW(TAG_DUMP, "Lunghezza zero");
        return;
    }
    
    ESP_LOGI(TAG_DUMP, "log_bytes of %p", data);
    waitForIt();

    // Buffer per la formattazione di una riga (3 caratteri per byte: 2 cifre hex + spazio)
    char buffer[16 * 3 + 1]; // Max 16 byte per riga + terminatore
    
    ESP_LOGI(TAG_DUMP, "Dump di %u bytes:", length);
    
    for (size_t offset = 0; offset < length; offset += 16) {
        // Determina quanti byte stampare in questa riga
        size_t line_bytes = (length - offset > 16) ? 16 : (length - offset);
        
        // Formatta la riga corrente
        memset(buffer, 0, sizeof(buffer));
        for (size_t i = 0; i < line_bytes; i++) {
            sprintf(buffer + i * 3, "%02x ", data[offset + i]);
        }
        
        // Stampa l'offset e i byte
        ESP_LOGI(TAG_DUMP, "0x%04x: %s", offset, buffer);
    }
}