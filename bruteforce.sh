#!/bin/bash

# Скрипт читает список IP адресов из файла, затем пробует подключиться к серверу под учеткой USER1 или USER2, используя 3 стандартных пароля. 
# В случае успешного подключения, выводит IP адрес и валидные креды от него.

# Чтение IP-адресов из файла и добавление их в массив или строку
IP_LIST_FILE="ip_list.txt"
LOG_FILE="ip_accessed_list_log.txt"
IP_ARRAY=()  # Массив для IP-адресов

# Прочитать IP-адреса из файла и добавить их в массив
while IFS= read -r ip; do
    IP_ARRAY+=("$ip")
done < "$IP_LIST_FILE"

# Преобразовать массив IP-адресов в строку через пробел
IP_STRING="${IP_ARRAY[@]}"

# Создание / очистка лог-файла
> $LOG_FILE

# Для каждого IP-адреса
for IP in "${IP_ARRAY[@]}"; do
    USER_ARRAY=("USER1" "USER2")
    PASS_ARRAY=("PASSWORD1" "PASSWORD2" "PASSWORD3")

    for USER in "${USER_ARRAY[@]}"; do
        for PASS in "${PASS_ARRAY[@]}"; do
            result=$(sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER"@"$IP" echo 'CONNECTED')
            if echo "$result" | grep -q "CONNECTED"; then
                echo "ПОДКЛЮЧЕНО! Host: $IP, username: $USER, password: $PASS" | tee -a $LOG_FILE
            # Для тестирования:    
            # else 
            #     echo "Безуспешная попытка подключения к $IP под пользователем $USER с паролем $PASS"
            fi
        done
    done
done
exit 1
