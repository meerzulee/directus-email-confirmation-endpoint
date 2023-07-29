import jwt from "jsonwebtoken";
import { createError } from "@directus/errors";

const InvalidPayloadError = (message) => {
  new createError("INVALID_PAYLOAD_ERROR", message, 500);
};

const ForbiddenException = (message) => {
  new createError(
    "FORBIDDEN",
    `You are not allowed to perform this operation. ${message}`,
    403
  );
};
const ServiceUnavailableException = (message) => {
  new createError("Service_Unavailable", message, 500);
};

export default (router, { services, exceptions, database, env }) => {
  const { UsersService } = services;
  router.post("/activate", async (req, res, next) => {
    try {
      const { token } = req.body;

      const { email, scope } = jwt.verify(token, env.SECRET, {
        issuer: "directus",
      });

      if (scope !== "invite")
        return next(
          ForbiddenException(`You are not allowed to perform this operation.`)
        );

      // Find user in DB by email
      const user = await database
        .select("id", "status")
        .from("directus_users")
        .where({ email })
        .first();

      // Check user status - must be "invited"
      if (user?.status !== "invited") {
        return next(
          InvalidPayloadError(`Email address ${email} hasn't been invited.`)
        );
      }

      const usersService = new UsersService({ schema: req.schema });
      await usersService.updateOne(user.id, { status: "active" });
      res.send("OK");
    } catch (error) {
      return next(ServiceUnavailableException(error.message));
    }
  });
};
