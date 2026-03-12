FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

# 安装curl用于健康检查
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# 创建非特权用户
RUN useradd -m -u 1000 ddnsuser && mkdir -p /app/data && chown -R ddnsuser:ddnsuser /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY templates/ ./templates/

# 确保数据目录权限正确
RUN chown -R ddnsuser:ddnsuser /app

# 切换到非特权用户
USER ddnsuser

EXPOSE 5000

CMD ["python", "-u", "app/main.py"]
