package nl.bruijnzeels.tim.rpki.ca.ta

import java.net.URI
import java.util.UUID
import org.joda.time.Period
import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.crl.X509Crl
import nl.bruijnzeels.tim.rpki.ca.common.domain.KeyPairSupport
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningMaterial
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningSupport
import nl.bruijnzeels.tim.rpki.ca.common.domain.ManifestRequest
import nl.bruijnzeels.tim.rpki.ca.common.domain.ManifestRequest
import java.math.BigInteger
import nl.bruijnzeels.tim.rpki.ca.common.domain.CrlRequest

case class TaPublicationSet(number: BigInteger, mft: ManifestCms, crl: X509Crl)

case class TaSigner(signingMaterial: SigningMaterial, publicationSet: Option[TaPublicationSet] = None, lastIssuedSerial: BigInteger = BigInteger.ZERO) {

  def applyEvent(event: TaSignerEvent): TaSigner = event match {
    case created: TaSignerCreated => TaSigner(created.signingMaterial)
    case publicationSetUpdated: TaPublicationSetUpdated => copy(publicationSet = Some(publicationSetUpdated.publicationSet))
    case certificateSigned: TaCertificateSigned => copy(lastIssuedSerial = certificateSigned.certificate.getSerialNumber())
  }

  def updatePublishedObjects(id: UUID): List[TaSignerEvent] = {

    val publicationSetNumber = publicationSet match {
      case None => BigInteger.ONE
      case Some(set) => set.number.add(BigInteger.ONE)
    }

    val crlRequest = CrlRequest(nextUpdateDuration = TaSigner.CrlNextUpdate, crlNumber = publicationSetNumber)
    val crl = SigningSupport.createCrl(signingMaterial, crlRequest)

    val mftRequest = ManifestRequest(nextUpdateDuration = TaSigner.MftNextUpdate,
      validityDuration = TaSigner.MftValidityTime,
      manifestNumber = publicationSetNumber,
      publishedObjects = List(crl),
      certificateSerial = lastIssuedSerial.add(BigInteger.ONE))
    val mft = SigningSupport.createManifest(signingMaterial, mftRequest)

    List(TaCertificateSigned(id, mft.getCertificate()),
      TaPublicationSetUpdated(id, TaPublicationSet(publicationSetNumber, mft, crl)))
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

  def applyEvents(events: List[TaEvent]): TrustAnchor = {
    events.foldLeft(this)((updated, event) => updated.applyEvent(event))
  }

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
      applyEvents(signer.get.updatePublishedObjects(id))
    }
  }

}

object TrustAnchor {

  def rebuild(events: List[TaEvent]): TrustAnchor = {
    TrustAnchor(events(0).id).applyEvents(events).copy(events = List())
  }

  def create(id: UUID, name: String): TrustAnchor = {
    TrustAnchor(id).applyEvent(TaCreated(id, name))
  }

}
