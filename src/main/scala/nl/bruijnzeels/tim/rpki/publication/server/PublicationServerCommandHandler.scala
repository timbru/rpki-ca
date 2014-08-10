package nl.bruijnzeels.tim.rpki.publication.server

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.EventStore
import java.util.UUID

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
    EventStore.store(server.events)
  }

  def dispatch(command: PublicationServerCommand) = {
    val existingServer = load(command.id)

    if (existingServer.isDefined && command.isInstanceOf[PublicationServerCreate]) {
      throw new IllegalArgumentException("Can't create new CA with id " + command.id + ", TA with same id exists")
    }

    if (!existingServer.isDefined && !command.isInstanceOf[PublicationServerCreate]) {
      throw new IllegalArgumentException("Can't find exisiting CA with id " + command.id + " for command")
    }

    val updatedCa = command match {
      case create: PublicationServerCreate => PublicationServerCreateHandler.handle(create)
    }

    save(updatedCa)
    updatedCa
  }
}

object PublicationServerCreateHandler {
  def handle(create: PublicationServerCreate) = PublicationServer.create(create.id)
}

sealed trait PublicationServerCommandHandler[C <: PublicationServerCommand] {
  def handle(command: C, server: PublicationServer): PublicationServer
}

