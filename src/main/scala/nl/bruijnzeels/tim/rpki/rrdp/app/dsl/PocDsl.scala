/**
 * Copyright (c) 2014-2015 Tim Bruijnzeels
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of this software, nor the names of its contributors, nor
 *     the names of the contributors' employers may be used to endorse or promote
 *     products derived from this software without specific prior written
 *     permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package nl.bruijnzeels.tim.rpki.rrdp.app.dsl

import scala.language.implicitConversions
import scala.language.postfixOps
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
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.EventStore
import nl.bruijnzeels.tim.rpki.ca.provisioning.MyIdentity
import nl.bruijnzeels.tim.rpki.publication.server.PublicationServerCommandDispatcher
import nl.bruijnzeels.tim.rpki.publication.server.PublicationServerCreate
import nl.bruijnzeels.tim.rpki.publication.server.PublicationServerUpdateListener
import nl.bruijnzeels.tim.rpki.publication.server.store.RrdpFilesDataSources
import nl.bruijnzeels.tim.rpki.publication.server.store.RrdpFilesStore
import nl.bruijnzeels.tim.rpki.rrdp.app.ApplicationOptions
import nl.bruijnzeels.tim.rpki.publication.disk.ObjectDiskWriter
import java.io.File
import org.h2.store.fs.FileUtils

/**
 * A DSL to support the proof of concept (PoC) set up
 * with a TA and child CA, publishing regularly,
 * and whatever else may be relevant for this..
 */
object PocDsl {

  import scala.language.implicitConversions

  implicit def stringToUri(s: String): URI = URI.create(s)
  implicit def stringToIpResourceSet(s: String): IpResourceSet = IpResourceSet.parse(s)

  val TrustAnchorCertUri: URI = ApplicationOptions.rsyncBaseUri.resolve("ta/ta.cer")
  val RrdpBaseUrl: URI = ApplicationOptions.rrdpBaseUri.resolve("rrdp/")
  val RrdpNotifyUrl: URI = ApplicationOptions.rrdpBaseUri.resolve("notify/notify.xml")

  val RsyncBaseUrl: URI = ApplicationOptions.rsyncBaseUri
  val RsyncBaseDir: File = ApplicationOptions.rsyncBaseDir

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

    def trustAnchor() = TrustAnchorCommandDispatcher.dispatch(
      TrustAnchorCreate(
        aggregateId = TrustAnchorId,
        name = TrustAnchorName,
        resources = TrustAnchorResources,
        taCertificateUri = TrustAnchorCertUri,
        publicationUri = RsyncBaseUrl,
        rrdpNotifyUrl = RrdpNotifyUrl))

    def certificateAuthority(id: UUID) = CertificateAuthorityCommandDispatcher.dispatch(
      CertificateAuthorityCreate(
        aggregateId = id,
        name = ChildName,
        baseUrl = RsyncBaseUrl,
        rrdpNotifyUrl = RrdpNotifyUrl))

    def publicationServer() = PublicationServerCommandDispatcher.dispatch(PublicationServerCreate(PublicationServerId, RrdpBaseUrl))
    
    

  }

  object current {
    def trustAnchor() = TrustAnchorCommandDispatcher.load(TrustAnchorId).get
    def taVersion = trustAnchor.versionedId
    
    def certificateAuthority(id: UUID) = CertificateAuthorityCommandDispatcher.load(id).get
    def caVersion(id: UUID) = certificateAuthority(id).versionedId
    
    def publicationServer() = PublicationServerCommandDispatcher.load(PublicationServerId).get
    val rrdpFileStore = new RrdpFilesStore(RrdpFilesDataSources.DurableDataSource)

    EventStore.subscribe(rrdpFileStore)
  }

  object trustAnchor {

    class taAddingChild(child: CertificateAuthority) {
      def withResources(resources: IpResourceSet) = {
        
        TrustAnchorCommandDispatcher.dispatch(
          TrustAnchorAddChild(
            versionedId = current taVersion,
            childId = child.versionedId.id,
            childXml = child.communicator.me.toChildXml,
            childResources = ChildResources))
      }
    }

    def addChild(child: CertificateAuthority) = new taAddingChild(child)

    def publish() = TrustAnchorCommandDispatcher.dispatch(TrustAnchorPublish(current taVersion))

  }

  class certificateAuthority(me: CertificateAuthority) {

    def addTa(parent: TrustAnchor) = {
      CertificateAuthorityCommandDispatcher.dispatch(
        CertificateAuthorityAddParent(
          versionedId = me.versionedId,
          parentXml = parent.communicator.getParentXmlForChild(ChildId).get))
    }

    def update() = {
      val parentId = UUID.fromString(me.communicator.parent.get.parentHandle)
      ChildParentResourceCertificateUpdateSaga.updateCertificates(parentId, me.versionedId.id)
    }

    def publish() = CertificateAuthorityCommandDispatcher.dispatch(CertificateAuthorityPublish(me.versionedId))

  }

  object certificateAuthority {
    def withId(id: UUID) = new certificateAuthority(me = (current certificateAuthority id))
  }

  object publicationServer {
    def listen() = EventStore.subscribe(new PublicationServerUpdateListener(PublicationServerId))

    def notificationFile() = {
      current publicationServer () notificationFile
    }
  }
  
  object diskWriter {
    val writer = ObjectDiskWriter(RsyncBaseUrl, RsyncBaseDir)
    
    if (!RsyncBaseDir.exists()) {
      FileUtils.createDirectories(RsyncBaseDir.getPath())
    }
    
    def listen() = writer.listen
  }
  

}