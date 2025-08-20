
TARGET MACHINE IP ADDRESS

10.129.66.53

---

# TASKS

### Task 1

O que significa a sigla de três letras FTP?
R: File Transfer Protocol


## Task 2

Em qual porta o serviço FTP geralmente escuta?
R: 21


## Task 3

O FTP envia dados em texto claro, sem qualquer criptografia. Qual sigla é usada para um protocolo posterior projetado para fornecer funcionalidade semelhante ao FTP, mas de forma segura, como uma extensão do protocolo SSH?
R: SFTP


## Task 4

Qual é o comando que podemos usar para enviar uma solicitação de eco ICMP para testar nossa conexão com o alvo?
R: Ping


## Task 5

A partir dos seus scans, qual versão do FTP está em execução no alvo?

Comando: nmap -p21 10.129.66.53 -sV

Saida:

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
Service Info: OS: Unix
```

R: vsftpd 3.0.3


## Task 6

A partir dos seus scans, qual tipo de sistema operacional está em execução no alvo?