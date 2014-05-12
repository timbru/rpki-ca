package nl.bruijnzeels.tim.rpki.ca.ta

import java.security.KeyPair
import nl.bruijnzeels.tim.rpki.ca.common.domain.KeyPairSupport
import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder

case class TrustAnchor(name: String = "", resources: IpResourceSet = new IpResourceSet, keyPair: Option[KeyPair] = None, events: List[TaEvent] = List()) {

  def applyEvent(event: TaEvent): TrustAnchor = event match {
    case created: TaCreated => copy(name = created.name, events = events :+ event)
    case resourcesUpdated: TaResourcesUpdated => copy(resources = resourcesUpdated.resources, events = events :+ event)
    case keyPairCreated: TaKeyPairCreated => copy(keyPair = Some(keyPairCreated.keyPair), events = events :+ event)
  }

  def createTrustAnchorCertificate() = {
    val certificate = new X509ResourceCertificateBuilder()
           .withCa(true)
           .withResources(resources)
           .withSigningKeyPair(keyPair.get)
           .build()
    this
  }

  def updateResources(resources: IpResourceSet) = {
    applyEvent(TaResourcesUpdated(resources))
  }

  def createKey(): TrustAnchor = {
    applyEvent(TaKeyPairCreated(KeyPairSupport.createRpkiKeyPair))
  }
}

object TrustAnchor {

  def rebuild(events: List[TaEvent]): TrustAnchor = {
    var ta = TrustAnchor()
    for (e <- events) {
      ta = ta.applyEvent(e)
    }
    ta.copy(events = List())
  }

  def create(name: String): TrustAnchor = {
    val ta = TrustAnchor()
    ta.applyEvent(TaCreated(name))
  }

}
