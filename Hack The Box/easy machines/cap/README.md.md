# CAP (Hack The Box)

**Dificuldade:** Easy  
**Plataforma:** Hack The Box - Easy Machines

## Resumo

CAP é uma máquina Linux de dificuldade *Easy* que roda um servidor HTTP responsável por funções administrativas, incluindo a realização de capturas de tráfego de rede. Controles inadequados causam uma Referência Direta Insegura a Objetos (IDOR), permitindo o acesso à captura de outro usuário. A captura contém credenciais em texto plano que podem ser usadas para obter um foothold. Em seguida, uma capability do Linux é explorada para escalar privilégios até root.

**Relatório detalhado:** [report.md](./report.md)

