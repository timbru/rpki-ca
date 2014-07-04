package nl.bruijnzeels.tim.rpki.ca.ta

import java.net.URI
import java.util.UUID
import net.ripe.ipresource.IpResourceSet
import org.scalatest.FunSuite
import org.scalatest.Matchers
import nl.bruijnzeels.tim.rpki.ca.common.domain.KeyPairSupport
import nl.bruijnzeels.tim.rpki.ca.common.domain.RpkiObjectNameSupport
import nl.bruijnzeels.tim.rpki.ca.core.Child
import nl.bruijnzeels.tim.rpki.ca.signer.Signer
import nl.bruijnzeels.tim.rpki.ca.signer.SignerCreated
import nl.bruijnzeels.tim.rpki.ca.signer.SignerSignedCertificate

abstract class TrustAnchorTest extends FunSuite with Matchers {

  val TrustAnchorName = "root"
  val TrustAnchorId = UUID.fromString("fdff6f65-1d4d-4940-8193-7c71911a2ec5")
  val TrustAnchorResources: IpResourceSet = "10/8"
  val TrustAnchorCertificateUri: URI = "rsync://localhost/ta.cer"
  val TrustAnchorPublicationUri: URI = "rsync://localhost/ta/"

  val TrustAnchorChildId = UUID.fromString("b716cfff-a58c-426c-81bf-096ae78abed7")

  val created = TaCreated(TrustAnchorId, TrustAnchorName)

  val taSignerCreateEvents = Signer.createSelfSigned(TrustAnchorId, TrustAnchorName, TrustAnchorResources, TrustAnchorCertificateUri, TrustAnchorPublicationUri)
  val signerCreated = taSignerCreateEvents(0).asInstanceOf[SignerCreated]
  val taCertificateSelfSigned = taSignerCreateEvents(1).asInstanceOf[SignerSignedCertificate]

  val TrustAnchorKeyPair = signerCreated.signingMaterial.keyPair

  val ChildPublicationUri: URI = s"rsync://localhost/${TrustAnchorChildId}/"
  val ChildPublicationMftUri: URI = ChildPublicationUri.resolve("child.mft")
  val ChildKeyPair = KeyPairSupport.createRpkiKeyPair
  val ChildSubject = RpkiObjectNameSupport.deriveSubject(ChildKeyPair.getPublic())

  //  val childCreated = TaChildAdded(TrustAnchorId, Child(TrustAnchorId, TrustAnchorChildId))

  def givenUninitialisedTa: TrustAnchor = TrustAnchor.rebuild(List(created))
  def givenInitialisedTa: TrustAnchor = TrustAnchor.rebuild(List(created, signerCreated))
  //  def givenTaWithChild: TrustAnchor = TrustAnchor.rebuild(List(created, signerCreated, childCreated))
}
