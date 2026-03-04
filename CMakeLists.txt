idf_component_register(SRCS "WiFiManager.c"
                       REQUIRES esp_wifi nvs_flash esp_http_server esp_event
                       INCLUDE_DIRS "include"
)