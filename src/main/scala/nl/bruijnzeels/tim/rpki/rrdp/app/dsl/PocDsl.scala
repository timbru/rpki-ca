package nl.bruijnzeels.tim.rpki.rrdp.app.dsl

import scala.language.implicitConversions
import java.net.URI
import java.util.UUID
import net.ripe.ipresource.IpResourceSet
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ChildParentResourceCertificateUpdateSaga
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ca.CertificateAuthority
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ca.CertificateAuthorityAddParent
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ca.CertificateAuthorityCommandDispatcher
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ca.CertificateAuthorityCreate
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ca.CertificateAuthorityPublish
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchor
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorAddChild
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorCommandDispatcher
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorCreate
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorPublish
import nl.bruijnzeels.tim.rpki.ca.provisioning.MyIdentity
import nl.bruijnzeels.tim.rpki.publication.server.PublicationServerCommandDispatcher
import nl.bruijnzeels.tim.rpki.publication.server.PublicationServerCreate

/**
 * A DSL to support the proof of concept (PoC) set up
 * with a TA and child CA, publishing regularly,
 * and whatever else may be relevant for this..
 */
object PocDsl {

  import scala.language.implicitConversions

  implicit def stringToUri(s: String): URI = URI.create(s)
  implicit def stringToIpResourceSet(s: String): IpResourceSet = IpResourceSet.parse(s)

  val TrustAnchorCertUri: URI = "http://localhost:8080/ta/ta.cer"
  val RrdpNotifyUrl: URI = "rrdp://localhost:8080/rrdp/notify.xml"
  val RsyncBaseUrl: URI = "rsync://localhost:10873/repository/"

  val PublicationServerId = UUID.fromString("8cb580ef-de6d-4435-94fd-ceaaddff3b99")

  val TrustAnchorId = UUID.fromString("f3ec94ee-ae80-484a-8d58-a1e43bbbddd1")
  val TrustAnchorName = "TA"
  val TrustAnchorResources = IpResourceSet.ALL_PRIVATE_USE_RESOURCES

  val ChildId = UUID.fromString("3a87a4b1-6e22-4a63-ad0f-06f83ad3ca16")
  val ChildName = "CA"
  val ChildIdentity = MyIdentity.create(ChildId)
  val ChildXml = ChildIdentity.toChildXml
  val ChildResources: IpResourceSet = "192.168.0.0/16"

  object create {

    def ta() = TrustAnchorCommandDispatcher.dispatch(
      TrustAnchorCreate(
        id = TrustAnchorId,
        name = TrustAnchorName,
        resources = TrustAnchorResources,
        taCertificateUri = TrustAnchorCertUri,
        publicationUri = RsyncBaseUrl,
        rrdpNotifyUrl = RrdpNotifyUrl))

    def ca(id: UUID) = CertificateAuthorityCommandDispatcher.dispatch(
      CertificateAuthorityCreate(
        id = id,
        name = ChildName,
        baseUrl = RsyncBaseUrl,
        rrdpNotifyUrl = RrdpNotifyUrl))

    def publicationServer() = PublicationServerCommandDispatcher.dispatch(PublicationServerCreate(PublicationServerId))

  }

  object current {
    def ta = TrustAnchorCommandDispatcher.load(TrustAnchorId).get
    def ca(id: UUID) = CertificateAuthorityCommandDispatcher.load(id).get
  }

  object ta {

    class taAddingChild(child: CertificateAuthority) {
      def withResources(resources: IpResourceSet) = {
        TrustAnchorCommandDispatcher.dispatch(
          TrustAnchorAddChild(
            id = TrustAnchorId,
            childId = child.id,
            childXml = child.communicator.me.toChildXml,
            childResources = ChildResources))
      }
    }

    def addChild(child: CertificateAuthority) = new taAddingChild(child)

    def publish() = TrustAnchorCommandDispatcher.dispatch(TrustAnchorPublish(TrustAnchorId))

  }

  class ca(me: CertificateAuthority) {

    def addTa(parent: TrustAnchor) = {
      CertificateAuthorityCommandDispatcher.dispatch(
        CertificateAuthorityAddParent(
          id = ChildId,
          parentXml = parent.communicator.getParentXmlForChild(ChildId).get))
    }

    def update() = {
      val parentId = UUID.fromString(me.communicator.parent.get.parentHandle)
      ChildParentResourceCertificateUpdateSaga.updateCertificates(parentId, me.id)
    }

    def publish() = CertificateAuthorityCommandDispatcher.dispatch(CertificateAuthorityPublish(me.id))

  }

  object ca {
    def withId(id: UUID) = new ca(me = (current ca id))
  }

}