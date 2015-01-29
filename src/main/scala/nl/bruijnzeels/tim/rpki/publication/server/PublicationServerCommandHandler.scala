package nl.bruijnzeels.tim.rpki.publication.server

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.EventStore
import java.util.UUID
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.VersionedId

object PublicationServerCommandDispatcher {

  def load(id: UUID): Option[PublicationServer] = {
    val events = EventStore.retrieve(id)
    if (events.size == 0) {
      None
    } else {
      Some(PublicationServer.rebuild(events).clearEventList())
    }
  }

  def save(server: PublicationServer) = {
    EventStore.store(server.events, server.versionedId.next)
  }

  def dispatch(command: PublicationServerCommand) = {
    val serverId = command.versionedId.id
    val existingServer = load(serverId)

    if (existingServer.isDefined && command.isInstanceOf[PublicationServerCreate]) {
      throw new IllegalArgumentException(s"Can't create new CA with id ${serverId}, TA with same id exists")
    }

    if (!existingServer.isDefined && !command.isInstanceOf[PublicationServerCreate]) {
      throw new IllegalArgumentException(s"Can't find exisiting CA with id ${serverId} for command")
    }

    val updatedCa = command match {
      case create: PublicationServerCreate => PublicationServerCreateHandler.handle(create)
      case publish: PublicationServerPublish => PublicationServerPublishHandler.handle(publish, existingServer.get)
    }

    save(updatedCa)
    updatedCa
  }
}

object PublicationServerCreateHandler {
  def handle(create: PublicationServerCreate) = PublicationServer.create(create.aggregateId, create.rrdpBaseUri)
}

sealed trait PublicationServerCommandHandler[C <: PublicationServerCommand] {
  def handle(command: C, server: PublicationServer): PublicationServer
}

object PublicationServerPublishHandler extends PublicationServerCommandHandler[PublicationServerPublish] {
  def handle(command: PublicationServerPublish, server: PublicationServer) = server.publish(command.messages)
}

