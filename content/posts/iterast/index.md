---
title: Iterast
date: 2024-01-21
draft: False
banner: header.png
banner_desc: View around Torr Head, Northern Ireland
---

I'll start off this blog with a post on something I hacked up a few days ago.

As most devs know, your productivity really depends on how fast you can iterate
on something.
So in the vain of that, I hacked up a small little util called `iterast`
("iterative ast"), that will reload a python project you are working on.
The reason this is mildly interesting is that it uses the python AST to be a
bit more considerate of when it runs and reruns sections of the code.

So it can:
* Determine which code block changes, and only rerun everything after that.
* Track files in the directory that are imported, rerunning if those get
  changed.

Obviously, this is a pretty similar concept to notebooks.
Main reason for writing this, beyond being fun, is that I primarily work on
the command line (and often via ssh) so it was just a bit more convenient for my
workflow.
I've also been burned a bit too many times by running notebook cells out of
order, making variables have invalid values.
That is the reason for rerunning every cell that occurs after a change, which
doesn't entirely resolve all the cases, but I don't want to implement knowledge
of the scope yet.

Anyway, here is a video demo of it:
{{< youtube FjP6IyULLFQ >}}

You can find the source code in the repo: [@bahorn/iterast](https://github.com/bahorn/iterast)

Been using it for some projects I'm currently working on, and not too bad of an
experience, though still hitting some bugs and writing fixes for now.

## Implementation Details

The core idea needs a few things:
* Tracking which files got changed.
* Ability to check which parts of the file got changed.
* Knowing if a module got changed.

### Tracking File changes

I used the [Watchdog library](https://pypi.org/project/watchdog/) to implement
this, which wasn't a bad choice for a cross platform library implementing this.

So I just used the basic Observer class to track changes to a directory, and it
emitted the sort of events I cared about.

### Finding out where the files changed.

This is one incredibly lazy trick.
The `ast` module returns an instance of `ast.Module()` when you call 
`ast.parse()` on some code.
This module class has an attribute called `body`, which is just a list of
statements inside it, so you can iterate though those and compare them.

The easiest method to compare was just to use `ast.unparse()`, which will give
you a string representation to compare against.

So something on the lines of the following works:
```python
for a, b in zip(original.body, parsed.body):
    if ast.unparse(a) != ast.unparse(b):
        print('found')
```

### Knowing if a module got changed

First, we need to know what modules we care about, which I resolved by a quick
search for `ast.Import` and `ast.ImportFrom` using the `ast.NodeTraversal` class.

```python
class FindImports(ast.NodeVisitor):
    def __init__(self):
        self._modules = []

    def modules(self):
        return self._modules

    def visit_Import(self, node):
        self._modules += list(map(lambda x: x.name, node.names))

    def visit_ImportFrom(self, node):
        self._modules.append(node.module)

def find_module_paths(ast):
    fi = FindImports()
    fi.visit(ast)
    return fi.modules()
```

Then, when we receive a `FileModifiedEvent()` from watchdog, we can check if
the path being modified looks like a module we are importing.

One thing that is a bit weak in this implementation is mapping module names to
filenames, but its not too hard of a fix.
