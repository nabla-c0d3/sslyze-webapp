from pathlib import Path

from invoke import task, Context

root_path = Path(__file__).parent.absolute()


@task
def lint(ctx):
    # type: (Context) -> None
    ctx.run("flake8 .")
    ctx.run("mypy .")
    ctx.run("black -l 120 main.py tasks.py --check")


@task
def test(ctx):
    # type: (Context) -> None
    ctx.run("pytest")
