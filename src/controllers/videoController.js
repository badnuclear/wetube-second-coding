export const trending = (req, res) => res.render("Home");
export const see = (req, res) => {
  return res.render("watch");
};
export const edit = (req, res) => res.render("edit");
export const search = (req, res) => res.send("Search");
export const upload = (req, res) => res.send("Upload");
export const deleteVideo = (req, res) => {
  console.log(req.params);
  return res.send("Delete Video");
};
