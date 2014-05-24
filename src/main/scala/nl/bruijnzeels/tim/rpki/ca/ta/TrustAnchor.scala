package nl.bruijnzeels.tim.rpki.ca.ta

import java.net.URI
import java.util.UUID

import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.crl.X509Crl

import nl.bruijnzeels.tim.rpki.ca.common.domain.KeyPairSupport
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningMaterial
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningSupport

import org.joda.time.Period

case class TaSigner(signingMaterial: SigningMaterial, mft: Option[ManifestCms] = None, crl: Option[X509Crl] = None) {
  
  def applyEvent(event: TaSignerEvent): TaSigner = event match {
    case created: TaSignerCreated => TaSigner(created.signingMaterial)
    case published: TaSignerPublished => copy(mft = Some(published.mft), crl = Some(published.crl)) 
  }
  
  def updatePublishedObjects(id: UUID): TaSignerPublished = {
    val crl = SigningSupport.createCrl(signingMaterial, TaSigner.CrlNextUpdate)
    val mft = SigningSupport.createManifest(signingMaterial, TaSigner.MftNextUpdate, TaSigner.MftValidityTime)
    
    TaSignerPublished(id, crl, mft)
  }
  
  
  
}

object TaSigner {
  
  val TrustAnchorLifeTime = Period.years(5)
  val CrlNextUpdate = Period.hours(24)
  val MftNextUpdate = Period.days(1)
  val MftValidityTime = Period.days(7)
  
  def create(id: UUID, name: String, resources: IpResourceSet, taCertificateUri: URI, publicationDir: URI): TaSignerCreated = {
    val keyPair = KeyPairSupport.createRpkiKeyPair
    val certificate = SigningSupport.createRootCertificate(name, keyPair, resources, publicationDir, TrustAnchorLifeTime) 

    TaSignerCreated(id, SigningMaterial(keyPair, certificate, taCertificateUri))
  }
}

case class TrustAnchor(id: UUID, name: String = "", signer: Option[TaSigner] = None, events: List[TaEvent] = List()) {

  def applyEvent(event: TaEvent): TrustAnchor = event match {
    case error: TaError => this // Errors must not have side-effects
    case created: TaCreated => copy(name = created.name, events = events :+ event)
    case signerCreated: TaSignerCreated => copy(signer = Some(TaSigner(signerCreated.signingMaterial)), events = events :+ event)
    case signerEvent: TaSignerEvent => copy(signer = Some(signer.get.applyEvent(signerEvent)), events = events :+ event)
  }

  def initialise(resources: IpResourceSet, taCertificateUri: URI, publicationDir: URI) = {
    applyEvent(TaSigner.create(id, name, resources, taCertificateUri, publicationDir))
  }
  
  def publish() = {
    if (signer.isEmpty) {
      applyEvent(TaError(id, "Trying to publish before initialising TrustAnchor"))
    } else {
      applyEvent(signer.get.updatePublishedObjects(id))
    }
  }
  
  
}

object TrustAnchor {

  def rebuild(events: List[TaEvent]): TrustAnchor = {
    var ta = TrustAnchor(events(0).id)
    for (e <- events) {
      ta = ta.applyEvent(e)
    }
    ta.copy(events = List())
  }

  def create(id: UUID, name: String): TrustAnchor = {
    val ta = TrustAnchor(id)
    ta.applyEvent(TaCreated(id, name))
  }

}
