## diggo
### domain information  gathering in go

Script que proporciona información de un dominio de diferentes fuentes de información:

* Consultas DNS
* Whois
* RIPE (Si se obtiene la empresa en Whois)
* Fuerza bruta para descubrimiento de subdominios.

## Instalación
Instalar los prerrequisitos

```
$ go get github.com/likexian/whois-go
```
Y posteriormente compilar el script
.
```
$ go build diggo.go

```

## Uso básico
```
$ diggo -domain dominio.com
```
### Parámetros
- -domain: especifica el dominio objetivo.
- -dictionary: modifica el diccionario por defecto para el descubrimiento de subdominios.
- -update: si se establece en "yes" descara la base de datos de RIPE

```
$ diggo -domain dominio.com -dictionay /usr/share/wordlist/mydic.txt -update yes
```
