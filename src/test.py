#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: Jérémy BEAUME


class A:
    def __init__(self):
        pass

    def foo(self, a, b, c):
        print "A.foo"


class B:
    def __init__(self):
        pass

    def foo(self, a, b):
        print "B.foo"


b = B()
b.foo(1, 2, 3)
