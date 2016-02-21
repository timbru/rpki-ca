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

import nl.bruijnzeels.tim.rpki.common.cqrs.{EventStore, TrustAnchorAggregate}

object TrustAnchorCommandDispatcher {

  def load(id: UUID): Option[TrustAnchor] = {
    val events = EventStore.retrieve(TrustAnchorAggregate, id)
    if (events.size == 0) {
      None
    } else {
      Some(TrustAnchor.rebuild(events).clearEventList())
    }
  }

  def save(ta: TrustAnchor) = {
    EventStore.store(ta)
  }


  def dispatch(command: TrustAnchorCommand) = {
    val taId = command.versionedId.id
    val existingTa = load(taId)

    if (existingTa.isDefined && command.isInstanceOf[TrustAnchorCreate]) {
      throw new IllegalArgumentException(s"Can't create new TA with id ${taId}, TA with same id exists")
    }

    if (!existingTa.isDefined && !command.isInstanceOf[TrustAnchorCreate]) {
      throw new IllegalArgumentException(s"Can't find existing TA with id ${taId} for command")
    }

    val updatedTa = command match {
      case create: TrustAnchorCreate => TrustAnchorCreateCommandHandler.handle(create)
      case publish: TrustAnchorPublish => TrustAnchorPublishCommandHandler.handle(publish, existingTa.get)
      case addChild: TrustAnchorAddChild => TrustAnchorAddChildCommandHandler.handle(addChild, existingTa.get)
      case resourceListQuery: TrustAnchorProcessResourceListQuery => TrustAnchorProcessResourceListQueryCommandHandler.handle(resourceListQuery, existingTa.get)
    }

    save(updatedTa)
    updatedTa
  }
}

object TrustAnchorCreateCommandHandler {
  def handle(command: TrustAnchorCreate) = TrustAnchor.create(command.aggregateId, command.name, command.taCertificateUri, command.publicationUri, command.rrdpNotifyUrl, command.resources)
}

trait TrustAnchorCommandHandler[C <: TrustAnchorCommand] {
  def handle(command: C, ta: TrustAnchor): TrustAnchor
}

object TrustAnchorPublishCommandHandler extends TrustAnchorCommandHandler[TrustAnchorPublish] {
  override def handle(command: TrustAnchorPublish, ta: TrustAnchor) = ta.publish()
}

object TrustAnchorAddChildCommandHandler extends TrustAnchorCommandHandler[TrustAnchorAddChild] {
  override def handle(command: TrustAnchorAddChild, ta: TrustAnchor) = ta.addChild(command.childId, command.childXml, command.childResources)
}

object TrustAnchorProcessResourceListQueryCommandHandler extends TrustAnchorCommandHandler[TrustAnchorProcessResourceListQuery] {
  override def handle(command: TrustAnchorProcessResourceListQuery, ta: TrustAnchor) = ta.processListQuery(command.childId, command.provisioningCmsObject).updatedParent.asInstanceOf[TrustAnchor]
}

