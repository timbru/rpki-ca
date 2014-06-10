package nl.bruijnzeels.tim.rpki.ca.ta

import java.net.URI
import java.util.UUID
import net.ripe.ipresource.IpResourceSet
import org.scalatest.FunSuite
import org.scalatest.Matchers
import nl.bruijnzeels.tim.rpki.ca.common.domain.KeyPairSupport
import nl.bruijnzeels.tim.rpki.ca.common.domain.RpkiObjectNameSupport

abstract class TrustAnchorTest extends FunSuite with Matchers {

  val TrustAnchorName = "root"
  val TrustAnchorId = UUID.fromString("fdff6f65-1d4d-4940-8193-7c71911a2ec5")
  val TrustAnchorResources: IpResourceSet = "10/8"
  val TrustAnchorCertificateUri: URI = "rsync://localhost/ta.cer"
  val TrustAnchorPublicationUri: URI = "rsync://localhost/ta/"
    
  val TrustAnchorChildId = UUID.fromString("b716cfff-a58c-426c-81bf-096ae78abed7")

  val created = TaCreated(TrustAnchorId, TrustAnchorName)
  val signerCreated = TaSigner.create(TrustAnchorId, TrustAnchorName, TrustAnchorResources, TrustAnchorCertificateUri, TrustAnchorPublicationUri)
  val TrustAnchorKeyPair = signerCreated.signingMaterial.keyPair

  
  val ChildPublicationUri: URI = s"rsync://localhost/${TrustAnchorChildId}/"
  val ChildPublicationMftUri: URI = ChildPublicationUri.resolve("child.mft")
  val ChildKeyPair = KeyPairSupport.createRpkiKeyPair
  val ChildSubject = RpkiObjectNameSupport.deriveSubject(ChildKeyPair.getPublic()) 

  val childCreated = TaChildAdded(TrustAnchorId, Child(TrustAnchorId, TrustAnchorChildId))


  def givenUninitialisedTa: TrustAnchor = TrustAnchor.rebuild(List(created))
  def givenInitialisedTa: TrustAnchor = TrustAnchor.rebuild(List(created, signerCreated))
  def givenTaWithChild: TrustAnchor = TrustAnchor.rebuild(List(created, signerCreated, childCreated))
}
