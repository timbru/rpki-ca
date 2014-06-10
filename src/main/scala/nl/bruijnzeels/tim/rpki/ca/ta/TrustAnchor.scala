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
import net.ripe.rpki.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayload
import net.ripe.ipresource.IpResourceType
import scala.collection.JavaConverters._
import nl.bruijnzeels.tim.rpki.ca.common.domain.IpResourceSupport

case class ChildKey(publicKey: PublicKey, currentCertificate: Option[X509ResourceCertificate])
case class ChildResourceClass(name: String, entitledResources: IpResourceSet, knownKeys: List[ChildKey] = List.empty)

case class Child(taId: UUID, id: UUID, resourceClasses: List[ChildResourceClass] = List.empty, log: List[String] = List.empty) {

  def applyEvent(event: TaChildEvent) = event match {
    case rcAdded: TaChildResourceClassAdded => copy(resourceClasses = resourceClasses :+ ChildResourceClass(rcAdded.entitlement.resourceClassName, rcAdded.entitlement.entitledResources))
    case rcRemoved: TaChildResourceClassRemoved => copy(resourceClasses = resourceClasses.filterNot(_.name == rcRemoved.name))
    case requestRejected: TaChildCertificateRequestRejected => copy(log = log :+ requestRejected.reason)
    case _ => ???
  }

  def updateEntitlements(entitlements: List[ResourceEntitlement]): List[TaChildEvent] = {
    findNewEntitlements(entitlements).map(ne => TaChildResourceClassAdded(taId, id, ne)) ++
      findRemovedResourceClasses(entitlements).map(rc => TaChildResourceClassRemoved(taId, id, rc.name))
  }

  private def findNewEntitlements(entitlements: List[ResourceEntitlement]) = {
    val existingResourceClassNames = resourceClasses.map(_.name)
    entitlements.filter(ne => !existingResourceClassNames.contains(ne.resourceClassName))
  }

  private def findExistingResourceClasses(entitlements: List[ResourceEntitlement]) = {
    val currentRCNames = entitlements.map(_.resourceClassName)
    resourceClasses.filter(rc => currentRCNames.contains(rc.name))
  }

  private def findRemovedResourceClasses(entitlements: List[ResourceEntitlement]) = {
    val currentRCNames = entitlements.map(_.resourceClassName)
    resourceClasses.filter(rc => !currentRCNames.contains(rc.name))
  }

}

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
    case signerEvent: TaSignerEvent => copy(signer = applySignerEvent(signerEvent), events = events :+ event)
    case childEvent: TaChildEvent => copy(children = applyChildEvent(childEvent), events = events :+ event)
  }

  private def applySignerEvent(signerEvent: TaSignerEvent) = Some(signer.get.applyEvent(signerEvent))

  private def applyChildEvent(childEvent: TaChildEvent) = {
    val updatedChild = getChild(childEvent.childId).applyEvent(childEvent)
    children.map { c => if (c.id == childEvent.childId) { updatedChild } else { c } }
  }

  // Signer support
  private def validateSignerExists(): Unit = if (signer.isEmpty) { throw new TrustAnchorException("No signer initialised") }
  private def validateSignerEmpty(): Unit = if (!signer.isEmpty) { throw new TrustAnchorException("Signer already initialised") }

  /**
   * Creates a signer for this TrustAnchor
   */
  def initialise(resources: IpResourceSet, taCertificateUri: URI, publicationDir: URI): TrustAnchor = {
    validateSignerEmpty()
    applyEvent(TaSigner.create(id, name, resources, taCertificateUri, publicationDir))
  }

  /**
   * Create a new publication set with an updated CRL and MFT for all current objects
   */
  def publish(): TrustAnchor = {
    validateSignerExists()
    applyEvents(signer.get.publish(id))
  }

  // Child management support

  private def findChild(childId: UUID): Option[Child] = children.find(_.id == childId)
  private def getChild(childId: UUID): Child = findChild(childId).getOrElse(throw new TrustAnchorException(s"Child with id ${childId} can not be found"))
  private def validateChildExists(childId: UUID): Unit = getChild(childId)
  private def validateChildDoesNotExist(childId: UUID): Unit = if (findChild(childId).isDefined) { throw new TrustAnchorException(s"Child with id: ${childId} already exists") }

  /**
   * Add a new child, throws exception if child already exists with same id
   */
  def addChild(childId: UUID): TrustAnchor = {
    validateChildDoesNotExist(childId)
    applyEvent(TaChildAdded(id, Child(taId = id, id = childId)))
  }

  /**
   * Update the resource entitlements for a child.
   *
   * Throws exception if child can not be found.
   */
  def childSetResourceEntitlements(childId: UUID, entitlements: List[ResourceEntitlement]) = {
    val child = getChild(childId)
    applyEvents(child.updateEntitlements(entitlements))
  }

  /**
   * Process child resource certificate request
   *
   * Throws exception if child can not be found.
   */
  def childProcessResourceCertificateRequest(childId: UUID, request: CertificateIssuanceRequestPayload) = {
    val child = getChild(childId)
    val resourceClassName = request.getRequestElement().getClassName()
    
    child.resourceClasses.find(_.name == resourceClassName) match {
      case None => applyEvent(TaChildCertificateRequestRejected(id, childId, "Unknown resource class: " + resourceClassName))
      case Some(rc) => {
        try {
        	val resources = IpResourceSupport.determineResources(rc.entitledResources, request)
        	
        	
            this
        } catch {
          case e: IllegalArgumentException => applyEvent(TaChildCertificateRequestRejected(id, childId, e.getMessage()))
        }
      }
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
