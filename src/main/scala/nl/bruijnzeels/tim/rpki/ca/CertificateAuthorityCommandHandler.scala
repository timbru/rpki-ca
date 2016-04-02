/**
 * Copyright (c) 2014-2016 Tim Bruijnzeels
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
package nl.bruijnzeels.tim.rpki.ca

import java.util.UUID

import nl.bruijnzeels.tim.rpki.common.cqrs.{CertificationAuthorityAggregate, EventStore}

object CertificateAuthorityCommandDispatcher {

  def load(id: UUID): Option[CertificateAuthority] = {
    val events = EventStore.retrieve(CertificationAuthorityAggregate, id)
    if (events.size == 0) {
      None
    } else {
      Some(CertificateAuthority.rebuild(events).clearEventList())
    }
  }

  def save(ca: CertificateAuthority) = {
    EventStore.store(ca)
  }

  def dispatch(command: CertificateAuthorityCommand) = {
    val caId = command.versionedId.id
    val existingCa = load(caId)

    if (existingCa.isDefined && (command.isInstanceOf[CertificateAuthorityCreate] || command.isInstanceOf[CertificateAuthorityCreateAsTrustAnchor])) {
      throw new IllegalArgumentException(s"Can't create new CA with id ${caId} CA with same id exists")
    }

    if (!existingCa.isDefined && !(command.isInstanceOf[CertificateAuthorityCreate] || command.isInstanceOf[CertificateAuthorityCreateAsTrustAnchor])) {
      throw new IllegalArgumentException(s"Can't find existing CA with id ${caId} for command")
    }

    val updatedCa = command match {
      case create: CertificateAuthorityCreate => CertificateAuthorityCreateHandler.handle(create)
      case createAsTA: CertificateAuthorityCreateAsTrustAnchor => CertificateAuthorityCreateAsTrustAnchorHandler.handle(createAsTA)

      case addParent: CertificateAuthorityAddParent => CertificateAuthorityAddParentHandler.handle(addParent, existingCa.get)
      case addChild: CertificateAuthorityAddChild => CertificateAuthorityAddChildHandler.handle(addChild, existingCa.get)
      case updateChildResources: CertificateAuthorityUpdateChildResources => CertificateAuthorityUpdateChildResourcesHandler.handle(updateChildResources, existingCa.get)

      case addRoa: CertificateAuthorityAddRoa => CertificateAuthorityAddRoaHandler.handle(addRoa, existingCa.get)
      case removeRoa: CertificateAuthorityRemoveRoa => CertificateAuthorityRemoveRoaHandler.handle(removeRoa, existingCa.get)

      case publish: CertificateAuthorityPublish => CertificateAuthorityPublishHandler.handle(publish, existingCa.get)
    }

    save(updatedCa)
    updatedCa
  }
}

object CertificateAuthorityCreateHandler {
  def handle(create: CertificateAuthorityCreate) = CertificateAuthority.create(create.aggregateId, create.name, create.baseUrl, create.rrdpNotifyUrl)
}

object CertificateAuthorityCreateAsTrustAnchorHandler {
  def handle(create: CertificateAuthorityCreateAsTrustAnchor) = CertificateAuthority.createAsTrustAnchor(create.aggregateId, create.name, create.resources, create.certificateUrl, create.baseUrl, create.rrdpNotifyUrl)
}

trait CertificateAuthorityCommandHandler[C <: CertificateAuthorityCommand] {
  def handle(command: C, ca: CertificateAuthority): CertificateAuthority
}

object CertificateAuthorityAddParentHandler extends CertificateAuthorityCommandHandler[CertificateAuthorityAddParent] {
  override def handle(command: CertificateAuthorityAddParent, ca: CertificateAuthority) = ca.addParent(command.parentXml)
}

object CertificateAuthorityAddChildHandler extends CertificateAuthorityCommandHandler[CertificateAuthorityAddChild] {
  override def handle(command: CertificateAuthorityAddChild, ca: CertificateAuthority) =
    ca.addChild(childId = command.childId, childXml = command.childXml, childResources = command.childResources)
}

object CertificateAuthorityUpdateChildResourcesHandler extends CertificateAuthorityCommandHandler[CertificateAuthorityUpdateChildResources] {
  override def handle(command: CertificateAuthorityUpdateChildResources, ca: CertificateAuthority) =
    ca.updateChild(childId = command.childId, childResources = command.childResources)
}

object CertificateAuthorityAddRoaHandler extends CertificateAuthorityCommandHandler[CertificateAuthorityAddRoa] {
  override def handle(command: CertificateAuthorityAddRoa, ca: CertificateAuthority) = ca.addRoa(command.roaAuthorisation)
}

object CertificateAuthorityRemoveRoaHandler extends  CertificateAuthorityCommandHandler[CertificateAuthorityRemoveRoa] {
  override def handle(command: CertificateAuthorityRemoveRoa, ca: CertificateAuthority)  = ca.removeRoa(command.roaAuthorisation)
}

/**
  * Creates new mft and crl, but also ensure that ROAs are updated according to ROA Configs and certified
  * space in each resource class
  */
object CertificateAuthorityPublishHandler extends CertificateAuthorityCommandHandler[CertificateAuthorityPublish] {
  override def handle(command: CertificateAuthorityPublish, ca: CertificateAuthority) = ca.publish
}