package nl.bruijnzeels.tim.rpki.ca.core

import java.math.BigInteger
import java.net.URI
import java.util.UUID
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.joda.time.Period
import net.ripe.ipresource.IpResourceSet
import nl.bruijnzeels.tim.rpki.ca.common.domain.ChildCertificateSignRequest
import nl.bruijnzeels.tim.rpki.ca.common.domain.KeyPairSupport
import nl.bruijnzeels.tim.rpki.ca.common.domain.Revocation
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningMaterial
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningSupport
import nl.bruijnzeels.tim.rpki.ca.ta.TaCertificateSigned
import nl.bruijnzeels.tim.rpki.ca.ta.TaPublicationSetUpdated
import nl.bruijnzeels.tim.rpki.ca.ta.TaRevocationAdded
import nl.bruijnzeels.tim.rpki.ca.ta.TaSignerCreated
import nl.bruijnzeels.tim.rpki.ca.ta.TaSignerEvent
import nl.bruijnzeels.tim.rpki.ca.ta.TaChildCertificateReceived
import nl.bruijnzeels.tim.rpki.ca.ta.TaCertificateSigned

case class Signer(
  signingMaterial: SigningMaterial,
  publicationSet: Option[PublicationSet] = None,
  children: Map[UUID, Child] = Map.empty,
  revocationList: List[Revocation] = List.empty) {

  import Signer._

  def applyEvent(event: TaSignerEvent): Signer = event match {
    case created: TaSignerCreated => Signer(created.signingMaterial)
    case published: TaPublicationSetUpdated => copy(publicationSet = Some(published.publicationSet))
    case signed: TaCertificateSigned => copy(signingMaterial = signingMaterial.updateLastSerial(signed.certificate.getSerialNumber()))
    case revoked: TaRevocationAdded => copy(revocationList = revocationList :+ revoked.revocation)
  }

  /**
   * Re-publish
   */
  def publish(caId: UUID) = publicationSet match {
    case None => PublicationSet.createFirst(caId, signingMaterial)
    case Some(set) => set.publish(caId, signingMaterial, children.values.toList.flatMap(c => c.currentCertificates))
  }

  /**
   * Sign a child certificate request
   */
  def signChildRequest(caId: UUID, childId: UUID, resources: IpResourceSet, pkcs10Request: PKCS10CertificationRequest) = {
    val childCaRequest = ChildCertificateSignRequest(
      pkcs10Request = pkcs10Request,
      resources = resources,
      validityDuration = ChildCaLifeTime,
      serial = signingMaterial.lastSerial.add(BigInteger.ONE))

    // if (! signingMaterial.currentCertificate.getResources().contains(resources)) { reject } 
    // if (! child.entitledResources.contains(resources)) { reject }

    val childCertificate = SigningSupport.createChildCaCertificate(signingMaterial, childCaRequest)

    List(TaCertificateSigned(caId, childCertificate), TaChildCertificateReceived(caId, childId, childCertificate))
  }

}

object Signer {

  val TrustAnchorLifeTime = Period.years(5)
  val ChildCaLifeTime = Period.years(1)
  val CrlNextUpdate = Period.hours(24)
  val MftNextUpdate = Period.days(1)
  val MftValidityTime = Period.days(7)

  def createSelfSigned(id: UUID, name: String, resources: IpResourceSet, taCertificateUri: URI, publicationDir: URI): List[TaSignerEvent] = {
    val keyPair = KeyPairSupport.createRpkiKeyPair
    val certificate = SigningSupport.createRootCertificate(name, keyPair, resources, publicationDir, TrustAnchorLifeTime)

    List(
      TaSignerCreated(id, SigningMaterial(keyPair, certificate, taCertificateUri, BigInteger.ZERO)),
      TaCertificateSigned(id, certificate))
  }

}