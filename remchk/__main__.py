import click
import sys
import remchk.web


def print_help(ctx, param, value):
    if value is True:
        click.echo(ctx.get_help())
        ctx.exit()


@click.group()
def main():
    pass


@main.command()
@click.option('-a', '--all', default=False, help='Check all vuls')
@click.option('-i', '--id', default='', help='by ID')
@click.option('-l', '--list', default=False, help='Show the list of vuls')
@click.option('-p', '--path', default=None, help='YAML file path')
@click.option('-s', '--schema', default=None, help='Show YAML schema')
@click.option('-t', '--host', default=False, help='Vulnerable hostname')
@click.option('-v', '--verbose', default=None, help='Verbose mode')
@click.option('-g', '--login', default=None, help='login test')
@click.pass_context
def web(ctx, all, id, list, path, schema, host, verbose, login):
    print_help(ctx, None, value=path is None)
    hWeb = remchk.web.Handler(path)
    # hWeb.login(login)
    # if schema is True:
    #     hWeb.print_schema()
    #     sys.exit(1)
    hWeb.try_all()

    # if all is True:
    #     hWeb.try_all()
    # elif schema is True:



if __name__ == '__main__':
    main()
