FROM python:3.12-slim

# ssh client + sshpass (installazione automatica della sonda con password usa-e-getta)
# nmap: scansione porte/servizi/OS dei server via Tailscale (solo binario di sistema, niente pip)
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client sshpass nmap \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# monitor-probe.py serve al collector per l'auto-install (endpoint /api/enroll)
COPY app.py dashboard.html login.html monitor-probe.py /app/

# nessuna dipendenza pip: tutto stdlib
EXPOSE 8888
CMD ["python3", "-u", "/app/app.py"]
