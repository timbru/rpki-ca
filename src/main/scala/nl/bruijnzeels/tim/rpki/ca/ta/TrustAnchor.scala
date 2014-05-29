package nl.bruijnzeels.tim.rpki.ca.ta

import java.math.BigInteger
import java.net.URI
import java.util.UUID
import org.joda.time.DateTime
import org.joda.time.Period
import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.crl.X509Crl
import nl.bruijnzeels.tim.rpki.ca.common.domain.CrlRequest
import nl.bruijnzeels.tim.rpki.ca.common.domain.KeyPairSupport
import nl.bruijnzeels.tim.rpki.ca.common.domain.ManifestRequest
import nl.bruijnzeels.tim.rpki.ca.common.domain.Revocation
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningMaterial
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningSupport
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import java.security.PublicKey


case class ChildKey(publicKey: PublicKey, currentCertificate: Option[X509ResourceCertificate])
case class ChildResourceClass(name: String, entitledResources: IpResourceSet, knownKeys: List[ChildKey] = List.empty)
case class Child(id: UUID, resourceClasses: List[ChildResourceClass] = List.empty)

case class TaPublicationSet(number: BigInteger, mft: ManifestCms, crl: X509Crl)

case class TaSigner(signingMaterial: SigningMaterial, publicationSet: Option[TaPublicationSet] = None, revocationList: List[Revocation] = List.empty, lastIssuedSerial: BigInteger = BigInteger.ZERO) {

  def applyEvent(event: TaSignerEvent): TaSigner = event match {
    case created: TaSignerCreated => TaSigner(created.signingMaterial)
    case publicationSetUpdated: TaPublicationSetUpdated => copy(publicationSet = Some(publicationSetUpdated.publicationSet))
    case certificateSigned: TaCertificateSigned => copy(lastIssuedSerial = certificateSigned.certificate.getSerialNumber())
    case revoked: TaRevocationAdded => copy(revocationList = revocationList :+ revoked.revocation)
  }

  /**
   * Create a new publication set with an updated CRL and MFT for all current objects
   *
   * @return: A list of events
   */
  def publish(id: UUID): List[TaSignerEvent] = {

    var publishEvents: List[TaSignerEvent] = List.empty

    val publicationSetNumber = publicationSet match {
      case None => BigInteger.ONE
      case Some(set) => set.number.add(BigInteger.ONE)
    }

    // revoke the old manifest if we have it
    val newRevocations = publicationSet match {
      case None => revocationList
      case Some(set) => {
        val oldMftCertificate = set.mft.getCertificate()
        val mftRevocation = Revocation(oldMftCertificate.getSerialNumber(), new DateTime(), oldMftCertificate.getValidityPeriod().getNotValidAfter())
        publishEvents = publishEvents :+ TaRevocationAdded(id, mftRevocation)
        revocationList :+ mftRevocation
      }
    }

    val crlRequest = CrlRequest(nextUpdateDuration = TaSigner.CrlNextUpdate, crlNumber = publicationSetNumber, revocations = newRevocations)
    val crl = SigningSupport.createCrl(signingMaterial, crlRequest)

    val mftRequest = ManifestRequest(nextUpdateDuration = TaSigner.MftNextUpdate,
      validityDuration = TaSigner.MftValidityTime,
      manifestNumber = publicationSetNumber,
      publishedObjects = List(crl),
      certificateSerial = lastIssuedSerial.add(BigInteger.ONE))
    val mft = SigningSupport.createManifest(signingMaterial, mftRequest)

    publishEvents = publishEvents ++ List(TaCertificateSigned(id, mft.getCertificate()),
      TaPublicationSetUpdated(id, TaPublicationSet(publicationSetNumber, mft, crl)))

    publishEvents
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

class TrustAnchorException(msg: String) extends RuntimeException(msg)

case class TrustAnchor(id: UUID, name: String = "", signer: Option[TaSigner] = None, children: List[Child] = List.empty, events: List[TaEvent] = List.empty) {

  def applyEvents(events: List[TaEvent]): TrustAnchor = {
    events.foldLeft(this)((updated, event) => updated.applyEvent(event))
  }

  def applyEvent(event: TaEvent): TrustAnchor = event match {
    case created: TaCreated => copy(name = created.name, events = events :+ event)
    case childAdded: TaChildAdded => copy(children = children :+ childAdded.child, events = events :+ event)
    case signerCreated: TaSignerCreated => copy(signer = Some(TaSigner(signerCreated.signingMaterial)), events = events :+ event)
    case signerEvent: TaSignerEvent => copy(signer = Some(signer.get.applyEvent(signerEvent)), events = events :+ event)
  }

  /**
   * Creates a signer for this TrustAnchor
   */
  def initialise(resources: IpResourceSet, taCertificateUri: URI, publicationDir: URI): TrustAnchor = {
    if (signer.isDefined) {
      throw new TrustAnchorException("This TA is already initialised")
    }
    applyEvent(TaSigner.create(id, name, resources, taCertificateUri, publicationDir))
  }

  /**
   * Create a new publication set with an updated CRL and MFT for all current objects
   */
  def publish(): TrustAnchor = {
    if (signer.isEmpty) {
      throw new TrustAnchorException("Trying to publish before initialising TrustAnchor")
    } else {
      applyEvents(signer.get.publish(id))
    }
  }
  
  /**
   * Add a new child, throws exception if child already exists with same id
   */
  def addChild(childId: UUID): TrustAnchor = {
    if (children.exists(_.id == childId)) {
      throw new TrustAnchorException(s"Child with id: ${childId} already exists")
    }
    applyEvent(TaChildAdded(id, Child(id = childId)))
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
