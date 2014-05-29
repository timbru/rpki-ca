package nl.bruijnzeels.tim.rpki.ca.ta

case class TaCommandDispatcher() {

  def dispatch(command: TaCommand) = {
    val existingTa = TaStore.load(command.id)

    if (existingTa.isDefined && command.isInstanceOf[TaCreate]) {
      throw new IllegalArgumentException("Can't create new TA with id " + command.id + ", TA with same id exists")
    }

    if (!existingTa.isDefined && !command.isInstanceOf[TaCreate]) {
      throw new IllegalArgumentException("Can't find exisiting TA with id " + command.id + " for command")
    }

    val updatedTa = command match {
      case create: TaCreate => TaCreateCommandHandler.handle(create)
      case publish: TaPublish => TaPublishCommandHandler.handle(publish, existingTa.get)
      case addChild: TaChildAdd => TaChildAddCommandHandler.handle(addChild, existingTa.get)
    }

    TaStore.save(updatedTa)
  }
}

object TaCreateCommandHandler {
  def handle(command: TaCreate) = TrustAnchor.create(command.id, command.name).initialise(command.resources, command.taCertificateUri, command.publicationUri)
}

trait TaCommandHandler[C <: TaCommand] {
  def handle(command: C, ta: TrustAnchor): TrustAnchor
}

object TaPublishCommandHandler extends TaCommandHandler[TaPublish] {
  override def handle(command: TaPublish, ta: TrustAnchor) = ta.publish()
}

object TaChildAddCommandHandler extends TaCommandHandler[TaChildAdd] {
  override def handle(command: TaChildAdd, ta: TrustAnchor) = ta.addChild(command.childId)
}

