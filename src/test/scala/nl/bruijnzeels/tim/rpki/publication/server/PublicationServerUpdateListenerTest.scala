package nl.bruijnzeels.tim.rpki.publication.server

import scala.language.postfixOps

import java.math.BigInteger

import nl.bruijnzeels.tim.rpki.ca.RpkiCaTest
import nl.bruijnzeels.tim.rpki.rrdp.app.dsl.PocDsl.create
import nl.bruijnzeels.tim.rpki.rrdp.app.dsl.PocDsl.publicationServer
import nl.bruijnzeels.tim.rpki.rrdp.app.dsl.PocDsl.trustAnchor

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class PublicationServerUpdateListenerTest extends RpkiCaTest {

    test("Should publish") {
      create publicationServer()
      publicationServer listen()

      (publicationServer notificationFile() serial) should equal (BigInteger.ZERO)

      create trustAnchor()
      trustAnchor publish()

      (publicationServer notificationFile() serial) should equal (BigInteger.ONE)
    }

}