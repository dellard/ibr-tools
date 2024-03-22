#!/usr/bin/env python3

# CODEMARK: nice-ibr
#
# Copyright (C) 2020-2024 - Raytheon BBN Technologies Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0.
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
#
# Distribution Statement "A" (Approved for Public Release,
# Distribution Unlimited).
#
# This material is based upon work supported by the Defense
# Advanced Research Projects Agency (DARPA) under Contract No.
# HR001119C0102.  The opinions, findings, and conclusions stated
# herein are those of the authors and do not necessarily reflect
# those of DARPA.
#
# In the event permission is required, DARPA is authorized to
# reproduce the copyrighted material for use as an exhibit or
# handout at DARPA-sponsored events and/or to post the material
# on the DARPA website.
#
# CODEMARK: end


class ArcObj:
    """

    Create a "arc" to represent a point in five-space.  The first two
    dimensions are used to define the x,y of the center of the arc
    (in Cartesian space).  The third and fourth dimensions are the
    pair of angles for the start and end of the arc, and the fifth
    dimension is the radius of the arc.  A sixth categorical dimension
    may also be specified, which is represented by color.

    Note that the third and fourth dimensions must be in the domain
    between 0 and 360, and if they are identical (or very close to
    each other) then the arc will be invisible or very hard to see.
    For our current plots, we use these two dimensions to represent
    a single categorical dimension, i.e. if we have four categories
    than we assign the first one (0, 90), the second (90, 180),
    the third (180, 270), and the last one (270, 360) so that each
    category gets an arc that looks like a quadrant.

    Here's what a gnuplot command to create an arc object looks like:

        set obj 2 circle at 0,3 size 3 arc [45:90]
                fs transparent solid 0.05 border rgb "green" lw 3

    Where the parameters are:

        obj OBJID - OBJID is an integer chosen by the caller.  It's up
            to the caller to remember which OBJIDs are already in use.
            (we'll let the ArcSet class handle this for us)

        at CENTERXY - CENTERXY is the x,y Cartesion coordinate of
            the center of the circle we're carving the arc out of.
            Note that 0,0 is at the lower left (like usual for gnuplot).

        size RADIUS - RADIUS is the radius of the circle

        arc ANGLES - ANGLES is in the form [STARTD:ENDD] where
            STARTD and ENDD are the starting/ending angles of the arc.
            Note that 0 is at "3 o'clock" and the degrees increase
            in a counter-clockwise order.  Degrees can be negative
            (i.e. [-10:10] is the same as [350:10]) and wrap around
            (i.e. [350:370] is the same as [350:10]).

        border COLOR - COLOR is an optional color spec, which can be
            the name of a color (i.e. "green" or "blue") or an RGB
            spec (which may be multiple tokens).

        [optional] lw LW - LW is the linewidth

    """

    def __init__(
            self, objid, centerxy, radius, angles,
            color='rgb "black"', width=None):

        self.objid = objid
        self.centerxy = centerxy
        self.radius = radius
        self.angles = angles
        self.color = color
        self.width = width

        if color is None:
            self.color = 'rgb "black"'

        # TODO: any error checking whatsoever

    def togp(self):

        text = 'set obj %d circle at %g,%g size %g arc [%g:%g]' % (
                self.objid, self.centerxy[0], self.centerxy[1],
                self.radius, self.angles[0], self.angles[1])
        if self.width:
            text += ' lw %s' % self.width

        # We could let the interior be completely transparent,
        # but it actually looks better in a lot of cases if it
        # is *slightly* opaque, to give it a more 3-d feeling
        #
        text += ' fs transparent solid 0.05 border %s' % self.color

        return text


class ArcSet:

    def __init__(self, min_visible=0):

        self.min_visible = min_visible

        self.objid = 1
        self.objects = list()

    def add(
            self, centerxy, radius, angles,
            color=None, width=None):

        # if the radius is leq min_visible, then don't create
        # an arc -- it will be too small to render properly
        # and will just gum up the display
        #
        if radius <= self.min_visible:
            return

        new_objid = self.objid
        self.objid += 1

        self.objects.append(
                ArcObj(new_objid, centerxy, radius, angles, color, width))

    def togp(self):
        return '\n'.join([arc.togp() for arc in self.objects])


class ArcPlot:

    def __init__(self, minx, miny, maxx, maxy, narcs):
        """
        Note that minx/miny/maxx/maxy etc are usually smaller/larger
        than the actual min and max, to give some margin around the
        outside of the plot (to leave room for the magnitudes of the
        values)
        """

        self.minx = minx
        self.miny = miny
        self.maxx = maxx
        self.maxy = maxy
        self.narcs = narcs

        self.arc_deg = 360.0 / float(self.narcs)

        self.arcs = ArcSet()

    def addv(self, x, y, values):
        for i in range(len(values)):
            span = (i * self.arc_deg, (i + 1) * self.arc_deg)
            self.arcs.add((x, y), values[i], span)

    def add(self, x, y, z, value):
        span = (z * self.arc_deg, (z + 1) * self.arc_deg)
        self.arcs.add((x, y), value, span)

    def togp(self, term=None, output=None, title=None):

        txt = ''
        if term:
            txt += 'set term \'%s\' size 600,600\n' % term
        if output:
            txt += 'set output \'%s\'\n' % output
        if title:
            txt += 'set key inside bottom right vertical\n'
            txt += 'set label \'%s\' offset graph 0.45, graph 0.03\n' % title

        txt += 'set xrange [%d:%d]\n' % (self.minx, self.maxx)
        txt += 'set yrange [%d:%d]\n' % (self.miny, self.maxy)

        txt += self.arcs.togp()
        txt += '\nplot %d notitle\n' % (self.miny - 1)

        return txt
