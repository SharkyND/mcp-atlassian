FROM mcr.microsoft.com/devcontainers/python:3.12
COPY --from=ghcr.io/astral-sh/uv:0.13.6 /uv /uvx /usr/local/bin/
ENV UV_LINK_MODE=copy
USER vscode
