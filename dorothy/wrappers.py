#
# Licensed to Elasticsearch under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

import click
from click_shell import Shell
from click_shell.core import ClickShell


PROMPT_STACK = []
HELP_ARGS = {"cmdlen": 15, "maxcol": 80}


def build_prompt():
    return " > ".join(PROMPT_STACK) + " > "


class ClickRootShell(ClickShell):
    """Wrapper around click shell for the root object."""

    prompt = staticmethod(build_prompt)

    def postcmd(self, stop: bool, line: str) -> bool:
        return ClickShell.postcmd(self, stop, line) or ClickSubShell.pending_exit

    def show_navigation_commands(self):
        """Show the navigation commands."""
        commands = sorted(["help", "quit", "exit"])
        self.print_topics("Navigation commands", commands, **HELP_ARGS)

    def show_global_commands(self):
        """Print the global commands."""
        group: click.Group = self.ctx.command
        commands = sorted(
            g for g in group.list_commands(self.ctx) if not isinstance(group.get_command(self.ctx, g), CustomShell)
        )
        self.print_topics("Global Commands", commands, **HELP_ARGS)

    def show_modules(self):
        """Print modules."""
        group: click.Group = self.ctx.command
        commands = sorted(
            g for g in group.list_commands(self.ctx) if isinstance(group.get_command(self.ctx, g), CustomShell)
        )
        self.print_topics("Modules", commands, **HELP_ARGS)

    def do_help(self, arg):
        if not (arg and arg.strip()):
            self.show_global_commands()
            self.show_modules()
            self.show_navigation_commands()
            click.echo("Type help <command> for detailed information")
        else:
            return ClickShell.do_help(self, arg)


class ClickSubShell(ClickShell):
    """Helper class for wrappers around ClickCmd."""

    pending_main = False
    pending_exit = False
    prompt = staticmethod(build_prompt)

    def do_back(self, text):
        """Return to the previous shell."""
        return True

    def do_exit(self, text):
        """Exit dorothy"""
        ClickSubShell.pending_exit = True
        return True

    def do_main(self, text):
        """Return to the main shell."""
        ClickSubShell.pending_main = True
        return True

    def help_back(self, text):
        return self.do_back.__doc__

    def help_exit(self, text):
        return self.do_exit.__doc__

    def help_main(self, text):
        return self.do_main.__doc__

    def precmd(self, line: str) -> str:
        ClickSubShell.pending_main = False
        ClickSubShell.pending_exit = False

        return ClickShell.precmd(self, line)

    def postcmd(self, stop: bool, line: str) -> bool:
        """Execute a single command and return whether the loop should exit."""
        return ClickShell.postcmd(self, stop, line) or ClickSubShell.pending_main or ClickSubShell.pending_exit

    def show_navigation_commands(self):
        """Show the navigation commands."""
        commands = sorted(["help", "quit", "exit", "main", "back"])
        self.print_topics("Navigation Commands", commands, **HELP_ARGS)

    def show_module_commands(self):
        """Show the module commands."""
        group: click.Group = self.ctx.command
        commands = sorted(group.list_commands(self.ctx))
        self.print_topics(f"Module Commands", commands, **HELP_ARGS)

    def do_help(self, arg):
        """Override the help method to be aware of global and local commands."""
        if not (arg and arg.strip()):
            click.echo()
            click.secho(self.ctx.command.name)
            click.echo(f"{'=' * len(self.ctx.command.name)}")
            click.echo(self.ctx.command.help)
            click.echo()

            self.show_module_commands()
            self.root.show_global_commands()
            self.show_navigation_commands()
        else:
            return ClickShell.do_help(self, arg)

    do_quit = do_exit
    help_quit = help_exit


class CustomShell(Shell):
    def __init__(self, shell_cls, **kwargs):
        self.kwargs = dict(kwargs)
        self.shell_cls = kwargs
        self.parent = kwargs.pop("parent", None)

        super(CustomShell, self).__init__(**kwargs)

        # re-cast the click shell as a ClickSubShell so all of the new methods are in scope
        self.shell.__class__ = shell_cls
        self.shell.prompt = (self.parent.shell.prompt if self.parent else "") + self.name + " > "

        # inherit all commands from the root scope
        self.inherit_root_commands()

    def inherit_root_commands(self, ctx=None):
        """Inherit commands from the root scope."""
        root = self

        while root.parent is not None:
            root = root.parent

        if root is not None:
            for name in root.list_commands(ctx):
                command = root.get_command(ctx, name)
                self.shell.add_command(command, command.name)

        self.shell.root = root and root.shell

    def subshell(self, *args, **kwargs):
        """Create a new decorator, like click.group that also creates a shell."""
        kwargs.update(shell_cls=ClickSubShell, cls=CustomShell, parent=self)
        return self.group(*args, **kwargs)

    def invoke(self, ctx):
        """Wrap the invoke() method so that the prompt gets updated for each subshell."""
        PROMPT_STACK.append(self.name)

        try:
            return super(CustomShell, self).invoke(ctx)
        finally:
            PROMPT_STACK.pop()


def rootshell(*args, **kwargs):
    """Decorator to turn a command into a root shell."""
    kwargs.update(shell_cls=ClickRootShell, cls=CustomShell)
    return click.group(*args, **kwargs)


def subshell(*args, **kwargs):
    """Decorator to turn a command into a sub-shell."""
    kwargs.update(shell_cls=ClickSubShell, cls=CustomShell)
    return click.group(*args, **kwargs)
