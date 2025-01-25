FROM python:3.12

WORKDIR /opt/applicatiion
ADD . .

RUN pip install -r requirements.txt
EXPOSE 443
EXPOSE 80

CMD ["python", "main.py"]