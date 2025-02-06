FROM python:3.12

WORKDIR /opt/application
ADD . .

RUN pip install -r requirements.txt
EXPOSE 443
EXPOSE 80
EXPOSE 8008

CMD ["python", "main.py"]