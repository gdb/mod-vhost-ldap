from pybench import Test

class TupleSlicing(Test):

    version = 0.31
    operations = 3 * 25 * 10 * 7
    rounds = 100

    def test(self):

        r = range(25)

        for i in xrange(self.rounds):

            t = tuple(range(100))

            for j in r:

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

                m = t[50:]
                m = t[:25]
                m = t[50:55]
                m = t[:-1]
                m = t[1:]
                m = t[-10:]
                m = t[:10]

    def calibrate(self):

        r = range(25)

        for i in xrange(self.rounds):

            t = tuple(range(100))

            for j in r:

                pass

class SmallTuples(Test):

    version = 0.3
    operations = 5*(1 + 3 + 6 + 2)
    rounds = 800*16

    def test(self):

        for i in xrange(self.rounds):

            t = (1,2,3,4,5,6)

            a,b,c,d,e,f = t
            a,b,c,d,e,f = t
            a,b,c,d,e,f = t

            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]

            l = list(t)
            t = tuple(l)

            t = (1,2,3,4,5,6)

            a,b,c,d,e,f = t
            a,b,c,d,e,f = t
            a,b,c,d,e,f = t

            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]

            l = list(t)
            t = tuple(l)

            t = (1,2,3,4,5,6)

            a,b,c,d,e,f = t
            a,b,c,d,e,f = t
            a,b,c,d,e,f = t

            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]

            l = list(t)
            t = tuple(l)

            t = (1,2,3,4,5,6)

            a,b,c,d,e,f = t
            a,b,c,d,e,f = t
            a,b,c,d,e,f = t

            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]

            l = list(t)
            t = tuple(l)

            t = (1,2,3,4,5,6)

            a,b,c,d,e,f = t
            a,b,c,d,e,f = t
            a,b,c,d,e,f = t

            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]
            a,b,c = t[:3]

            l = list(t)
            t = tuple(l)

    def calibrate(self):

        for i in xrange(self.rounds):
            pass
