
FROM python:3.10

WORKDIR /code

COPY cert/* /code/cert/
COPY replacements/* /code/replacements/

COPY av_gate.py requirements.txt /code/
COPY docker/av_gate.ini /code/
RUN pip install --no-cache-dir uvicorn
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

CMD ["uvicorn", "av_gate:app", "--host 0.0.0.0:443", "--port", "443"]

EXPOSE 443
