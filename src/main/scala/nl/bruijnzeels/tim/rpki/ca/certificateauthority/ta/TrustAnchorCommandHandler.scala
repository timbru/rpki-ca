package nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.EventStore
import java.util.UUID
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.VersionedId

object TrustAnchorCommandDispatcher {

  def load(id: UUID): Option[TrustAnchor] = {
    val events = EventStore.retrieve(id)
    if (events.size == 0) {
      None
    } else {
      Some(TrustAnchor.rebuild(events).clearEventList())
    }
  }

  def save(ta: TrustAnchor) = {
    EventStore.store(ta.events, ta.versionedId.next)
  }


  def dispatch(command: TrustAnchorCommand) = {
    val taId = command.versionedId.id
    val existingTa = load(taId)

    if (existingTa.isDefined && command.isInstanceOf[TrustAnchorCreate]) {
      throw new IllegalArgumentException(s"Can't create new TA with id ${taId}, TA with same id exists")
    }

    if (!existingTa.isDefined && !command.isInstanceOf[TrustAnchorCreate]) {
      throw new IllegalArgumentException(s"Can't find exisiting TA with id ${taId} for command")
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
  override def handle(command: TrustAnchorProcessResourceListQuery, ta: TrustAnchor) = ta.processListQuery(command.childId, command.provisioningCmsObject)
}

